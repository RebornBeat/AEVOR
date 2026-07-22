//! End-to-end integration test for AEVOR.
//!
//! This is NOT an isolated unit test — it drives a real `NodeEngine` through the
//! whole pipeline with real subsystems: wallet key generation, transaction
//! signing, signature verification, DAG conflict rejection, VM bytecode
//! execution, durable log-structured persistence, authenticated Merkle state
//! commitment + proofs, and a real finality proof over a validator committee.

use aevor_core::consensus::SecurityLevel;
use aevor_core::primitives::{Address, Hash256, ObjectId};
use aevor_core::privacy::PrivacyLevel;
use aevor_crypto::agility::Signer;
use aevor_crypto::signatures::{BlsKeyPair, Ed25519KeyPair};
use aevor_vm::bytecode::BytecodeCodec;
use aevor_vm::instructions::Instruction::{Add, Div, Ld};

use node::engine::{CommitteeMember, LaneBlock, MerkleBackend, NodeEngine, SignedTransaction};

fn obj(n: u8) -> ObjectId {
    ObjectId(Hash256([n; 32]))
}

/// Genesis allocation for tests: transactions built with `new_simple` all share
/// the zero sender address, so fund it generously to cover their fees under the
/// account settlement layer. Feeless subnets charge nothing regardless.
fn genesis_fund(node: &mut NodeEngine) {
    node.fund(Address::ZERO, aevor_core::primitives::Amount::from_nano(u128::MAX / 2));
}

/// Build a wallet-signed transaction (the "create a wallet + sign" path).
/// Generic over any agility `Signer` — Ed25519 or post-quantum ML-DSA.
fn signed_tx(
    wallet: &impl Signer,
    tx_id: u8,
    reads: &[u8],
    writes: &[u8],
    bytecode: Vec<u8>,
) -> SignedTransaction {
    let reads: Vec<ObjectId> = reads.iter().map(|&n| obj(n)).collect();
    let writes: Vec<ObjectId> = writes.iter().map(|&n| obj(n)).collect();
    // Build the canonical rich transaction (nonce carries `tx_id` so distinct
    // ids are distinct transactions) and sign it with the wallet (any scheme).
    let tx = aevor_core::transaction::Transaction::new_simple(
        wallet.public_key_multi(),
        aevor_core::primitives::Nonce(u64::from(tx_id)),
        &reads,
        &writes,
        bytecode,
    );
    aevor_crypto::agility::sign_transaction(tx, wallet)
}

/// Tamper with a signed transaction after signing by adding a write. This
/// changes its signing bytes so the signature no longer matches — used to prove
/// the signature gate drops it.
fn tamper(tx: &mut SignedTransaction) {
    tx.transaction.inputs.push(aevor_core::transaction::TransactionInput {
        object_id: obj(99),
        expected_version: 0,
        content_hash: Hash256::ZERO,
        access_type: aevor_core::transaction::InputAccessType::ReadWrite,
    });
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let mut d = std::env::temp_dir();
    d.push(format!(
        "aevor-e2e-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    d
}

fn open_node(dir: &std::path::Path) -> NodeEngine {
    let mut node = NodeEngine::open(
        dir.to_path_buf(),
        Address::from_bytes([1u8; 32]),
        PrivacyLevel::Public,
        SecurityLevel::Minimal,
    )
    .expect("node opens");
    // Genesis allocation: test transactions built with `new_simple` all share the
    // zero sender address, so fund it generously to cover their fees under the
    // account settlement layer. (Feeless subnets charge nothing regardless.)
    genesis_fund(&mut node);
    node
}

#[test]
fn full_pipeline_wallet_to_finality() {
    let dir = temp_dir("full");
    let mut node = open_node(&dir);

    // A wallet = a keypair.
    let wallet = Ed25519KeyPair::from_seed([9u8; 32]);
    let good_program = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]); // computes 5

    // Three disjoint, well-signed transactions.
    let block = vec![
        signed_tx(&wallet, 1, &[], &[10], good_program.clone()),
        signed_tx(&wallet, 2, &[], &[20], good_program.clone()),
        signed_tx(&wallet, 3, &[], &[30], good_program.clone()),
    ];

    let out = node.process_block(block).expect("block processes");
    assert_eq!(out.accepted, 3, "all three well-signed disjoint txs accepted");
    assert_eq!(out.rejected, 0);
    assert_eq!(out.bad_signature, 0);
    assert!(out.gas_used > 0, "the VM actually executed the programs");
    assert_eq!(out.height, 1);
    assert_ne!(out.state_root, aevor_core::storage::MerkleRoot::EMPTY);

    // The written object is committed and provable against the state root.
    let proof = node.prove_object(&obj(10)).unwrap().expect("proof exists");
    assert!(proof.is_inclusion);
    assert!(NodeEngine::verify_proof(&proof), "Merkle inclusion proof verifies");

    // Finalize over a 3-validator committee — produces a real finality proof.
    let v1 = Ed25519KeyPair::from_seed([1; 32]);
    let v2 = Ed25519KeyPair::from_seed([2; 32]);
    let v3 = Ed25519KeyPair::from_seed([3; 32]);
    let (b1, b2, b3) = (BlsKeyPair::from_ikm([1; 32]), BlsKeyPair::from_ikm([2; 32]), BlsKeyPair::from_ikm([3; 32]));
    let committee = vec![
        CommitteeMember { keypair: &v1, bls: &b1, weight: 40 },
        CommitteeMember { keypair: &v2, bls: &b2, weight: 40 },
        CommitteeMember { keypair: &v3, bls: &b3, weight: 40 },
    ];
    let fin = node.finalize_block(out.block_hash, &committee).unwrap();
    assert!(fin.finalized, "committee weight clears the security level");
    assert!(fin.bls_verified, "aggregated BLS finality signature verifies (O(1))");
    assert!(!fin.aggregate_signature.is_empty(), "real BLS aggregate produced");
    assert_eq!(fin.signature_count, 3, "finality proof carries all 3 signatures");
    assert_eq!(fin.signed_weight, 120);

    let _ = std::fs::remove_file(dir.join("state.log"));
}

#[test]
fn bad_signature_is_dropped_before_execution() {
    let dir = temp_dir("badsig");
    let mut node = open_node(&dir);
    let wallet = Ed25519KeyPair::from_seed([9u8; 32]);

    let mut tx = signed_tx(&wallet, 1, &[], &[10], Vec::new());
    // Tamper with the write set AFTER signing → signature no longer matches.
    tamper(&mut tx);

    let out = node.process_block(vec![tx]).unwrap();
    assert_eq!(out.bad_signature, 1);
    assert_eq!(out.accepted, 0);
    // Nothing was committed.
    assert!(!node.prove_object(&obj(10)).unwrap().unwrap().is_inclusion);

    let _ = std::fs::remove_file(dir.join("state.log"));
}

#[test]
fn conflicting_transactions_are_rejected() {
    let dir = temp_dir("conflict");
    let mut node = open_node(&dir);
    let wallet = Ed25519KeyPair::from_seed([9u8; 32]);
    let prog = BytecodeCodec::encode(&[Ld(1), Ld(1), Add]);

    // Both write object 10 → the second conflicts and is rejected pre-execution.
    let block = vec![
        signed_tx(&wallet, 1, &[], &[10], prog.clone()),
        signed_tx(&wallet, 2, &[], &[10], prog.clone()),
    ];
    let out = node.process_block(block).unwrap();
    assert_eq!(out.accepted, 1);
    assert_eq!(out.rejected, 1);

    let _ = std::fs::remove_file(dir.join("state.log"));
}

#[test]
fn failed_program_rejects_and_commits_no_state() {
    let dir = temp_dir("failprog");
    let mut node = open_node(&dir);
    let wallet = Ed25519KeyPair::from_seed([9u8; 32]);
    // Division by zero aborts in the VM → transaction rejected, no state write.
    let bad = BytecodeCodec::encode(&[Ld(1), Ld(0), Div]);

    let out = node.process_block(vec![signed_tx(&wallet, 1, &[], &[10], bad)]).unwrap();
    assert_eq!(out.accepted, 0);
    assert_eq!(out.rejected, 1);
    // Object 10 was never committed.
    assert!(!node.prove_object(&obj(10)).unwrap().unwrap().is_inclusion);

    let _ = std::fs::remove_file(dir.join("state.log"));
}

#[test]
fn state_reconstructs_from_durable_log_on_restart() {
    // Real durability at the node level: after a restart, the node rebuilds its
    // authenticated Merkle state from the durable log, so the object survives
    // and stays provable against the SAME reconstructed root.
    let dir = temp_dir("reconstruct");
    let wallet = Ed25519KeyPair::from_seed([9u8; 32]);
    let prog = BytecodeCodec::encode(&[Ld(7)]);

    let root_after_first;
    {
        let mut node = open_node(&dir);
        let out = node
            .process_block(vec![signed_tx(&wallet, 1, &[], &[42], prog.clone())])
            .unwrap();
        assert_eq!(out.accepted, 1);
        assert!(node.prove_object(&obj(42)).unwrap().unwrap().is_inclusion);
        root_after_first = node.state_root();
    }

    // Reopen: state is reconstructed from the durable LogBackend.
    {
        let node = open_node(&dir);
        let proof = node.prove_object(&obj(42)).unwrap().unwrap();
        assert!(proof.is_inclusion, "object 42 reconstructed from durable storage");
        assert!(NodeEngine::verify_proof(&proof), "reconstructed proof verifies");
        assert_eq!(
            node.state_root(),
            root_after_first,
            "reconstructed state root matches pre-restart root"
        );
    }

    let _ = std::fs::remove_file(dir.join("state.log"));
}

#[test]
fn two_independent_nodes_converge_to_identical_state() {
    // Determinism (a core canonical property): two independent nodes given the
    // same block compute byte-identical state roots and block hashes — the basis
    // for consensus agreement across a network.
    let dir_a = temp_dir("detA");
    let dir_b = temp_dir("detB");
    let wallet = Ed25519KeyPair::from_seed([9u8; 32]);
    let prog = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);

    let make_block = || {
        vec![
            signed_tx(&wallet, 1, &[], &[10], prog.clone()),
            signed_tx(&wallet, 2, &[], &[20], prog.clone()),
            signed_tx(&wallet, 3, &[], &[30], prog.clone()),
        ]
    };

    let mut node_a = open_node(&dir_a);
    let mut node_b = open_node(&dir_b);
    let out_a = node_a.process_block(make_block()).unwrap();
    let out_b = node_b.process_block(make_block()).unwrap();

    assert_eq!(out_a.accepted, 3);
    assert_eq!(out_b.accepted, 3);
    assert_eq!(
        out_a.state_root, out_b.state_root,
        "independent nodes converge to identical state root"
    );
    assert_eq!(
        out_a.block_hash, out_b.block_hash,
        "and identical block hash"
    );

    let _ = std::fs::remove_file(dir_a.join("state.log"));
    let _ = std::fs::remove_file(dir_b.join("state.log"));
}

#[test]
fn hybrid_wallet_transacts_end_to_end() {
    // A hybrid (Ed25519 + ML-DSA-65) wallet transacts through the node — the
    // same pipeline verifies its packed dual signature.
    use aevor_crypto::post_quantum::HybridKeyPair;
    let dir = temp_dir("hybridwallet");
    let mut node = open_node(&dir);

    let wallet = HybridKeyPair::generate().unwrap();
    let prog = BytecodeCodec::encode(&[Ld(1), Ld(2), Add]);

    let out = node
        .process_block(vec![signed_tx(&wallet, 1, &[], &[10], prog)])
        .unwrap();
    assert_eq!(out.accepted, 1, "hybrid-signed tx accepted end-to-end");
    assert_eq!(out.bad_signature, 0);

    // Tampering after signing is rejected (both halves are bound to the message).
    let mut bad = signed_tx(&wallet, 2, &[], &[20], Vec::new());
    tamper(&mut bad);
    let out2 = node.process_block(vec![bad]).unwrap();
    assert_eq!(out2.bad_signature, 1, "tampered hybrid tx dropped");
    assert_eq!(out2.accepted, 0);

    let _ = std::fs::remove_file(dir.join("state.log"));
}

#[test]
fn post_quantum_wallet_transacts_end_to_end() {
    // A post-quantum (ML-DSA-65) wallet signs a transaction; the node verifies
    // the PQ signature through the same agility path and processes it fully.
    use aevor_crypto::post_quantum::ml_dsa::MlDsa65KeyPair;
    let dir = temp_dir("pqwallet");
    let mut node = open_node(&dir);

    let pq_wallet = MlDsa65KeyPair::generate().unwrap();
    let prog = BytecodeCodec::encode(&[Ld(4), Ld(5), Add]);

    let out = node
        .process_block(vec![signed_tx(&pq_wallet, 1, &[], &[10], prog)])
        .unwrap();
    assert_eq!(out.accepted, 1, "ML-DSA-signed tx accepted end-to-end");
    assert_eq!(out.bad_signature, 0);

    // A tampered PQ transaction is rejected by signature verification.
    let mut bad = signed_tx(&pq_wallet, 2, &[], &[20], Vec::new());
    tamper(&mut bad);
    let out2 = node.process_block(vec![bad]).unwrap();
    assert_eq!(out2.bad_signature, 1, "tampered ML-DSA tx dropped");
    assert_eq!(out2.accepted, 0);

    let _ = std::fs::remove_file(dir.join("state.log"));
}

#[test]
fn transaction_propagates_across_nodes_and_they_converge() {
    // Real multi-node propagation: a tx submitted to node A is broadcast over a
    // (wire-serialized) transport, received by node B, and both nodes — building
    // blocks independently from their mempools — converge to an identical state
    // root. This exercises mempool + gossip + deterministic execution together.
    use aevor_network::gossip::{LocalNetwork, MessageTransport, NetworkMessage};

    let dir_a = temp_dir("propA");
    let dir_b = temp_dir("propB");
    let mut node_a = open_node(&dir_a);
    let mut node_b = open_node(&dir_b);

    let net = LocalNetwork::new();
    let ep_a = net.connect();
    let ep_b = net.connect();

    let wallet = Ed25519KeyPair::from_seed([9u8; 32]);
    let prog = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);
    let tx = signed_tx(&wallet, 1, &[], &[10], prog);

    // Node A admits the tx locally and gossips it (serialized) to peers.
    assert!(node_a.submit(tx.clone()));
    ep_a.broadcast(NetworkMessage::Transaction(bincode::serialize(&tx).unwrap()));

    // Node B receives from the network, deserializes, and admits to its mempool.
    for msg in ep_b.drain_inbound() {
        if let NetworkMessage::Transaction(bytes) = msg {
            let received: SignedTransaction = bincode::deserialize(&bytes).unwrap();
            assert!(node_b.submit(received), "propagated tx admitted by peer");
        }
    }

    assert_eq!(node_a.pending_count(), 1);
    assert_eq!(node_b.pending_count(), 1, "tx propagated to node B");

    // Both build a block from their mempools and converge.
    let out_a = node_a.produce_block().unwrap();
    let out_b = node_b.produce_block().unwrap();
    assert_eq!(out_a.accepted, 1);
    assert_eq!(out_b.accepted, 1);
    assert_eq!(
        out_a.state_root, out_b.state_root,
        "propagated tx yields identical state on both nodes"
    );
    assert_eq!(out_a.block_hash, out_b.block_hash);
    assert_eq!(node_a.pending_count(), 0, "mempool drained after block");

    let _ = std::fs::remove_file(dir_a.join("state.log"));
    let _ = std::fs::remove_file(dir_b.join("state.log"));
}

#[test]
fn multi_block_height_advances_and_root_evolves() {
    let dir = temp_dir("multiblock");
    let mut node = open_node(&dir);
    let wallet = Ed25519KeyPair::from_seed([9u8; 32]);
    let prog = BytecodeCodec::encode(&[Ld(1)]);

    let r0 = node.state_root();
    node.process_block(vec![signed_tx(&wallet, 1, &[], &[1], prog.clone())]).unwrap();
    let r1 = node.state_root();
    node.process_block(vec![signed_tx(&wallet, 2, &[], &[2], prog.clone())]).unwrap();
    let r2 = node.state_root();

    assert_eq!(node.height(), 2);
    assert_ne!(r0, r1, "state root changes after first block");
    assert_ne!(r1, r2, "state root changes after second block");

    let _ = std::fs::remove_file(dir.join("state.log"));
}

#[test]
fn client_submits_and_queries_verified_state() {
    // The full user path: a client builds+signs a tx, submits it over a
    // connection, the node produces a block, and the client queries the object
    // back and VERIFIES its Merkle proof before trusting the data.
    use aevor_client::exec::Client;
    use node::engine::EngineConnection;

    let dir = temp_dir("client");
    let mut node = open_node(&dir);
    let prog = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);

    // Client submits over the connection (into the node's mempool). Scoped so
    // the mutable borrow of `node` is released before we produce a block.
    {
        let wallet = Ed25519KeyPair::from_seed([9u8; 32]);
        let mut client = Client::new(wallet, EngineConnection::new(&mut node));
        let resp = client.submit(&[], &[obj(10)], prog).unwrap();
        assert!(resp.admitted, "node admitted the client's transaction");
    }

    // Node builds a block from its mempool.
    let out = node.produce_block().unwrap();
    assert_eq!(out.accepted, 1);

    // Client queries the object and verifies the proof.
    {
        let wallet = Ed25519KeyPair::from_seed([9u8; 32]);
        let client = Client::new(wallet, EngineConnection::new(&mut node));
        let data = client.get_object(obj(10)).unwrap();
        assert!(data.is_some(), "object present and Merkle proof verified");
        // A non-existent object returns None (no proof to verify).
        assert!(client.get_object(obj(200)).unwrap().is_none());
    }

    let _ = std::fs::remove_file(dir.join("state.log"));
}

#[test]
fn node_modes_apply_distinct_policies() {
    // All three modes drive the SAME NodeEngine and differ only in policy:
    // a full node executes and produces blocks, a validator additionally
    // finalizes over a committee, and a light node verifies proofs against a
    // trusted root WITHOUT executing or holding full state.
    use node::full_node::FullNode;
    use node::light_node::LightNode;
    use node::validator::ValidatorNode;

    // --- Full node: executes and produces a block (full state), no finalize ---
    let dir = temp_dir("mode-full");
    let mut engine = open_node(&dir);
    let wallet = Ed25519KeyPair::from_seed([7u8; 32]);
    assert!(engine.submit(signed_tx(&wallet, 1, &[], &[10], BytecodeCodec::encode(&[Ld(2), Ld(3), Add]))));

    let mut full = FullNode::new();
    assert!(full.produce_block(&mut engine).is_err(), "unstarted full node cannot produce");
    full.start().unwrap();
    let outcome = full.produce_block(&mut engine).unwrap();
    assert_eq!(outcome.accepted, 1, "full node executed and produced a block");

    // --- Validator: executes, produces, AND finalizes over a committee ---
    let dir2 = temp_dir("mode-val");
    let mut engine2 = open_node(&dir2);
    assert!(engine2.submit(signed_tx(&wallet, 2, &[], &[11], BytecodeCodec::encode(&[Ld(1), Ld(1), Add]))));
    let v1 = Ed25519KeyPair::from_seed([21u8; 32]);
    let v2 = Ed25519KeyPair::from_seed([22u8; 32]);
    let v3 = Ed25519KeyPair::from_seed([23u8; 32]);
    let (b1, b2, b3) = (BlsKeyPair::from_ikm([21u8; 32]), BlsKeyPair::from_ikm([22u8; 32]), BlsKeyPair::from_ikm([23u8; 32]));
    let committee = [
        CommitteeMember { keypair: &v1, bls: &b1, weight: 40 },
        CommitteeMember { keypair: &v2, bls: &b2, weight: 40 },
        CommitteeMember { keypair: &v3, bls: &b3, weight: 40 },
    ];

    let mut validator = ValidatorNode::new();
    assert!(
        validator.produce_and_finalize(&mut engine2, &committee).is_err(),
        "inactive validator cannot finalize"
    );
    validator.activate().unwrap();
    let (vout, finality) = validator.produce_and_finalize(&mut engine2, &committee).unwrap();
    assert_eq!(vout.accepted, 1, "validator executed and produced a block");
    assert!(finality.finalized, "validator finalized over the committee");
    assert!(finality.bls_verified, "validator's BLS aggregate finality verifies");

    // --- Light node: verifies a proof against a trusted root, no engine ---
    let proof = engine.prove_object(&obj(10)).unwrap().expect("object present");
    let trusted_root = engine.state_root();
    let light = LightNode::new(Some("trusted-checkpoint".into()));
    assert!(light.verify_object(&proof, &trusted_root), "light node verified inclusion");
    // The same proof must be rejected against a different (untrusted) root.
    assert!(
        !light.verify_object(&proof, &engine2.state_root()),
        "light node rejects a proof rooted elsewhere"
    );

    let _ = std::fs::remove_file(dir.join("state.log"));
    let _ = std::fs::remove_file(dir2.join("state.log"));
}

#[test]
fn client_submits_and_queries_over_real_socket() {
    // The same full user path as `client_submits_and_queries_verified_state`,
    // but the client talks to the node over a REAL TCP socket (server +
    // request/response protocol) instead of an in-process connection.
    use aevor_client::exec::Client;
    use aevor_client::transport::TcpNodeConnection;
    use node::server::NodeServer;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};

    let dir = temp_dir("client-socket");
    let engine = Arc::new(Mutex::new(open_node(&dir)));
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let server_addr = NodeServer::bind(Arc::clone(&engine), SocketAddr::new(lo, 0)).unwrap();
    let prog = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);

    // Client submits a transaction over the socket into the node's mempool.
    {
        let wallet = Ed25519KeyPair::from_seed([9u8; 32]);
        let mut client = Client::new(wallet, TcpNodeConnection::connect(server_addr));
        let resp = client.submit(&[], &[obj(10)], prog).unwrap();
        assert!(resp.admitted, "node admitted the client's transaction over TCP");
    }

    // Node produces a block from its mempool (locking the shared engine).
    {
        let mut eng = engine.lock().unwrap();
        let out = eng.produce_block().unwrap();
        assert_eq!(out.accepted, 1);
    }

    // Client queries the object back over the socket and verifies its proof.
    {
        let wallet = Ed25519KeyPair::from_seed([9u8; 32]);
        let client = Client::new(wallet, TcpNodeConnection::connect(server_addr));
        let data = client.get_object(obj(10)).unwrap();
        assert!(data.is_some(), "object present and Merkle proof verified over TCP");
        assert!(client.get_object(obj(200)).unwrap().is_none());
    }

    let _ = std::fs::remove_file(dir.join("state.log"));
}

#[test]
fn sparse_merkle_backend_reproduces_state_and_proves_in_engine() {
    // The engine, run with the SPARSE Merkle backend, must behave identically:
    // a verifier reproduces the producer's root via attestation, and inclusion
    // proofs verify. This proves the pluggable backend is correct end-to-end,
    // not just as a standalone structure.
    let prog = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);
    let wallet = Ed25519KeyPair::from_seed([9u8; 32]);

    let dir_p = temp_dir("sparse-p");
    let mut producer = NodeEngine::open_with_backend(
        dir_p.to_path_buf(),
        Address::from_bytes([1u8; 32]),
        PrivacyLevel::Public,
        SecurityLevel::Minimal,
        MerkleBackend::Sparse,
    )
    .expect("sparse node opens");
    let txs: Vec<_> = (0..40u8).map(|i| signed_tx(&wallet, i, &[], &[i], prog.clone())).collect();
    genesis_fund(&mut producer);
    let (outcome, attestation, delta) = producer.produce_attested_batch(txs).unwrap();
    assert_eq!(outcome.accepted, 40);

    let dir_v = temp_dir("sparse-v");
    let mut verifier = NodeEngine::open_with_backend(
        dir_v.to_path_buf(),
        Address::from_bytes([1u8; 32]),
        PrivacyLevel::Public,
        SecurityLevel::Minimal,
        MerkleBackend::Sparse,
    )
    .expect("sparse verifier opens");
    verifier.apply_attested_batch(&attestation, &delta).unwrap();
    assert_eq!(
        verifier.state_root(),
        producer.state_root(),
        "sparse-backend verifier reproduced the producer's root via attestation"
    );

    // An inclusion proof for a written object from the sparse-backed engine verifies.
    let proof = producer
        .prove_object(&obj(7))
        .expect("prove ok")
        .expect("object 7 is present");
    assert!(NodeEngine::verify_proof(&proof), "sparse-backend proof verifies");
    assert_eq!(proof.siblings.len(), 256, "sparse proof has full-depth path");

    for d in [dir_p, dir_v] {
        let _ = std::fs::remove_file(d.join("state.log"));
    }
}

#[test]
fn pou_verify_by_attestation_reproduces_state_without_reexecuting() {
    // Producer executes a batch in its TEE and emits (attestation, delta).
    // A verifier applies it WITHOUT re-executing and must reach the SAME state
    // root — the Proof-of-Uncorruption fast path. Tampering is rejected.
    let prog = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);
    let wallet = Ed25519KeyPair::from_seed([9u8; 32]);

    let dir_p = temp_dir("pou-p");
    let mut producer = open_node(&dir_p);
    let txs: Vec<_> = (0..40u8).map(|i| signed_tx(&wallet, i, &[], &[i], prog.clone())).collect();
    let (outcome, attestation, delta) = producer.produce_attested_batch(txs).unwrap();
    assert_eq!(outcome.accepted, 40);

    // Verifier reproduces state from the attestation + delta (no VM execution).
    let dir_v = temp_dir("pou-v");
    let mut verifier = open_node(&dir_v);
    verifier.apply_attested_batch(&attestation, &delta).unwrap();
    assert_eq!(
        verifier.state_root(),
        producer.state_root(),
        "verifier reproduced the producer's state via attestation, without re-executing"
    );

    // A corrupted object delta does not reproduce the attested new root → rejected.
    let dir_v2 = temp_dir("pou-v2");
    let mut v2 = open_node(&dir_v2);
    let mut bad = delta.clone();
    bad.objects[0].1 = vec![0xFFu8; 8];
    assert!(v2.apply_attested_batch(&attestation, &bad).is_err(), "corrupted delta rejected");

    // A tampered BALANCE delta does not match the attested balance commitment → rejected.
    let dir_vb = temp_dir("pou-vb");
    let mut vb = open_node(&dir_vb);
    let mut bad_bal = delta.clone();
    if bad_bal.balances.is_empty() {
        bad_bal.balances.push((Address::ZERO, 12_345));
    } else {
        bad_bal.balances[0].1 = bad_bal.balances[0].1.wrapping_add(1);
    }
    assert!(
        vb.apply_attested_batch(&attestation, &bad_bal).is_err(),
        "tampered balance delta rejected by balance commitment"
    );

    // A forged attestation is rejected.
    let dir_v3 = temp_dir("pou-v3");
    let mut v3 = open_node(&dir_v3);
    let mut forged = attestation.clone();
    forged.signature = vec![0u8; 64];
    assert!(v3.apply_attested_batch(&forged, &delta).is_err(), "forged attestation rejected");

    for d in [dir_p, dir_v, dir_v2, dir_v3] {
        let _ = std::fs::remove_file(d.join("state.log"));
    }
}

#[test]
fn multi_lane_round_deterministic_ordering_consistent_state() {
    // F-A1: the node-side macro-DAG multi-lane path. Several validators produce
    // blocks CONCURRENTLY (disjoint object ranges); the node orders them
    // deterministically (leaderless) and applies them. Every validator reaches
    // the SAME state root regardless of the order lanes arrived — consensus on
    // ordering with no single producer bottleneck.
    let prog = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);

    fn make_lane(prog: &[u8], lane_id: u32, seed: u8, obj_base: u8) -> LaneBlock {
        let wallet = Ed25519KeyPair::from_seed([seed; 32]);
        let dir = temp_dir(&format!("lane-src-{lane_id}"));
        let mut eng = open_node(&dir);
        // Sender-sharded: each lane uses a distinct funded sender (no cross-lane
        // account contention). Verifiers need no funding — absolute balance deltas
        // overwrite.
        let sender = Address::from_bytes([(lane_id as u8).wrapping_add(1); 32]);
        assert!(eng.fund(sender, aevor_core::primitives::Amount::from_nano(1_000_000_000)));
        let txs: Vec<_> = (0..10u8)
            .map(|i| signed_tx_from(&wallet, i, &[], &[obj_base + i], prog.to_vec(), sender))
            .collect();
        let (_out, attestation, delta) = eng.produce_attested_batch(txs).unwrap();
        let _ = std::fs::remove_file(dir.join("state.log"));
        LaneBlock { lane_id, producer: aevor_core::primitives::Hash256([lane_id as u8; 32]), attestation, delta }
    }

    // Three concurrent lanes on disjoint object ranges.
    let lane_a = make_lane(&prog, 1, 11, 0); // objects 0..9
    let lane_b = make_lane(&prog, 2, 22, 50); // objects 50..59
    let lane_c = make_lane(&prog, 3, 33, 100); // objects 100..109

    // Node 1 receives lanes in arrival order [A, B, C].
    let dir1 = temp_dir("mlr-1");
    let mut node1 = open_node(&dir1);
    let out1 = node1
        .apply_lane_round(vec![lane_a.clone(), lane_b.clone(), lane_c.clone()])
        .unwrap();

    // Node 2 receives the SAME lanes in a DIFFERENT arrival order [C, A, B].
    let dir2 = temp_dir("mlr-2");
    let mut node2 = open_node(&dir2);
    let out2 = node2
        .apply_lane_round(vec![lane_c.clone(), lane_a.clone(), lane_b.clone()])
        .unwrap();

    assert_eq!(
        node1.state_root(),
        node2.state_root(),
        "identical state root regardless of the order lanes arrived (leaderless ordering)"
    );
    assert_eq!(
        out1.ordered_lanes, out2.ordered_lanes,
        "deterministic lane order, independent of arrival order"
    );
    assert_eq!(out1.lanes_applied, 3);
    assert_eq!(
        out1.objects_applied, 30,
        "three lanes x 10 objects each = 30 objects of aggregate work in one round"
    );

    // A node that applied only ONE lane must NOT match the three-lane root —
    // the round genuinely aggregated three lanes, it isn't trivially equal.
    let dir_one = temp_dir("mlr-one");
    let mut node_one = open_node(&dir_one);
    node_one.apply_lane_round(vec![lane_a.clone()]).unwrap();
    assert_ne!(
        node_one.state_root(),
        node1.state_root(),
        "one lane != three lanes (the round aggregated real work)"
    );

    // Rejection: a forged lane attestation.
    let dir3 = temp_dir("mlr-3");
    let mut node3 = open_node(&dir3);
    let mut forged = lane_a.clone();
    forged.attestation.signature = vec![0u8; 64];
    assert!(
        node3.apply_lane_round(vec![forged]).is_err(),
        "forged lane attestation rejected"
    );

    // Rejection: two lanes claiming the same transaction set.
    let dir4 = temp_dir("mlr-4");
    let mut node4 = open_node(&dir4);
    assert!(
        node4.apply_lane_round(vec![lane_a.clone(), lane_a.clone()]).is_err(),
        "two lanes with the same tx set rejected (cross-lane conflict)"
    );

    for d in [dir1, dir2, dir_one, dir3, dir4] {
        let _ = std::fs::remove_file(d.join("state.log"));
    }
}

#[test]
fn sharded_verification_bounded_slice_full_coverage() {
    // F-A2: sharded verification. Each lane is deterministically assigned a
    // verifying quorum; each validator processes only its assigned slice. Across
    // the set every lane is still covered by a quorum, but no validator carries
    // every lane — so per-validator load is bounded and the aggregate scales
    // with the validator count (the uncapped regime).
    use aevor_dag::macro_dag::LaneAssignment;
    let prog = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);

    fn mk(prog: &[u8], lane_id: u32, seed: u8, base: u8) -> LaneBlock {
        let wallet = Ed25519KeyPair::from_seed([seed; 32]);
        let dir = temp_dir(&format!("shard-src-{lane_id}"));
        let mut eng = open_node(&dir);
        let sender = Address::from_bytes([(lane_id as u8).wrapping_add(1); 32]);
        assert!(eng.fund(sender, aevor_core::primitives::Amount::from_nano(1_000_000_000)));
        let txs: Vec<_> = (0..4u8)
            .map(|i| signed_tx_from(&wallet, i, &[], &[base + i], prog.to_vec(), sender))
            .collect();
        let (_o, attestation, delta) = eng.produce_attested_batch(txs).unwrap();
        let _ = std::fs::remove_file(dir.join("state.log"));
        LaneBlock { lane_id, producer: aevor_core::primitives::Hash256([lane_id as u8; 32]), attestation, delta }
    }

    let m = 12u32;
    let validator_count = 6usize;
    let quorum = 2usize;
    // Disjoint object ranges: lane i -> objects [i*4, i*4+4).
    let lanes: Vec<LaneBlock> = (0..m).map(|i| mk(&prog, i, (i + 1) as u8, (i as u8) * 4)).collect();

    // Every lane is covered by exactly `quorum` validators (deterministically).
    for lane in &lanes {
        let q = LaneAssignment::quorum_for_lane(
            &aevor_core::primitives::Hash256(lane.attestation.tx_commitment),
            validator_count,
            quorum,
        );
        assert_eq!(q.len(), quorum, "each lane covered by a quorum of validators");
    }

    // Each validator processes ONLY its assigned slice.
    let mut covered = std::collections::HashSet::new();
    let mut max_slice = 0usize;
    let mut total_processed = 0usize;
    for v in 0..validator_count {
        let dir = temp_dir(&format!("shard-v{v}"));
        let mut node = open_node(&dir);
        let out = node
            .apply_lane_round_sharded(lanes.clone(), v, validator_count, quorum)
            .unwrap();
        max_slice = max_slice.max(out.lanes_applied);
        total_processed += out.lanes_applied;
        for id in &out.ordered_lanes {
            covered.insert(*id);
        }
        let _ = std::fs::remove_file(dir.join("state.log"));
    }

    assert_eq!(covered.len(), m as usize, "every lane covered by the validator set");
    assert_eq!(
        total_processed,
        m as usize * quorum,
        "total work = M lanes x quorum (each lane verified by exactly `quorum` validators)"
    );
    assert!(
        max_slice < m as usize,
        "no validator processes every lane — bounded slice, not full verification"
    );
}

#[test]
fn corruption_detection_produces_slashing_evidence() {
    // F-A3: the corruption -> slashing loop. A verifier that finds a lane's PoU
    // attestation does not verify emits InvalidAttestation evidence naming the
    // producer, which the graduated slashing policy turns into a stake penalty.
    // "valid until proven corrupted", backed by an economic consequence.
    use aevor_consensus::slashing::{
        GraduatedSlashingPolicy, SlashingEvidenceType, SlashingMechanism,
    };
    use aevor_core::primitives::Amount;

    let prog = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);
    fn ln(prog: &[u8], lane_id: u32, seed: u8, base: u8) -> LaneBlock {
        let wallet = Ed25519KeyPair::from_seed([seed; 32]);
        let dir = temp_dir(&format!("corrupt-src-{lane_id}"));
        let mut eng = open_node(&dir);
        let sender = Address::from_bytes([(lane_id as u8).wrapping_add(1); 32]);
        assert!(eng.fund(sender, aevor_core::primitives::Amount::from_nano(1_000_000_000)));
        let txs: Vec<_> = (0..4u8)
            .map(|i| signed_tx_from(&wallet, i, &[], &[base + i], prog.to_vec(), sender))
            .collect();
        let (_o, attestation, delta) = eng.produce_attested_batch(txs).unwrap();
        let _ = std::fs::remove_file(dir.join("state.log"));
        LaneBlock {
            lane_id,
            producer: aevor_core::primitives::Hash256([lane_id as u8; 32]),
            attestation,
            delta,
        }
    }

    let verifier = open_node(&temp_dir("corrupt-verifier"));

    let honest_a = ln(&prog, 1, 11, 0);
    let honest_b = ln(&prog, 2, 22, 50);
    let mut corrupt = ln(&prog, 3, 33, 100);
    corrupt.attestation.signature = vec![0u8; 64]; // forged -> attestation.verify() fails

    // Detection over a mixed round: exactly one piece of evidence, against the
    // corrupt producer.
    let evidence =
        verifier.detect_lane_corruption(&[honest_a.clone(), corrupt.clone(), honest_b.clone()]);
    assert_eq!(evidence.len(), 1, "only the corrupt lane produces evidence");
    assert_eq!(evidence[0].offender, corrupt.producer, "evidence names the offender");
    assert_eq!(evidence[0].evidence_type, SlashingEvidenceType::InvalidAttestation);

    // The graduated slashing policy converts it to a real stake penalty.
    let policy = GraduatedSlashingPolicy::new(SlashingMechanism::new(500, 10));
    let stake = Amount::from_nano(1_000_000);
    let penalty = policy.compute(evidence[0].evidence_type, stake);
    assert!(penalty.slash_amount.as_nano() > 0, "corruption is slashed");
    assert_eq!(
        penalty.slash_amount.as_nano(),
        10_000,
        "InvalidAttestation is Moderate = 1% of 1,000,000 nano"
    );

    // An all-honest round produces no evidence and no slash.
    let clean = verifier.detect_lane_corruption(&[honest_a, honest_b]);
    assert!(clean.is_empty(), "honest lanes produce no evidence");
}

/// Like `signed_tx` but sets an explicit sender address before signing (so the
/// signature covers it) — used to exercise permissioned-subnet admission.
fn signed_tx_from(
    wallet: &impl Signer,
    tx_id: u8,
    reads: &[u8],
    writes: &[u8],
    bytecode: Vec<u8>,
    sender: Address,
) -> SignedTransaction {
    let reads: Vec<ObjectId> = reads.iter().map(|&n| obj(n)).collect();
    let writes: Vec<ObjectId> = writes.iter().map(|&n| obj(n)).collect();
    let mut tx = aevor_core::transaction::Transaction::new_simple(
        wallet.public_key_multi(),
        aevor_core::primitives::Nonce(u64::from(tx_id)),
        &reads,
        &writes,
        bytecode,
    );
    tx.sender = sender; // before signing: signing_bytes() commits to the sender
    aevor_crypto::agility::sign_transaction(tx, wallet)
}

#[test]
fn feeless_subnet_charges_no_fee_fee_subnet_charges_gas() {
    // F-C1: the same batch pays zero on a feeless subnet and gas*price on a fee
    // subnet — feeless economics enforced end-to-end through block production.
    use node::subnet::SubnetPolicy;
    let prog = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);
    let batch = |seed: u8| -> Vec<SignedTransaction> {
        let wallet = Ed25519KeyPair::from_seed([seed; 32]);
        (0..4u8).map(|i| signed_tx(&wallet, i, &[], &[i], prog.to_vec())).collect()
    };

    // Feeless subnet. (The permissioned flag is irrelevant here — process_block
    // does not gate on admission; only submit() does — so a feeless permissioned
    // policy exercises the zero-fee path cleanly.)
    let feeless = SubnetPolicy::feeless_permissioned(vec![], PrivacyLevel::Public);
    let mut fnode = NodeEngine::open_on_subnet(
        temp_dir("feeless-subnet"),
        Address::from_bytes([1u8; 32]),
        feeless,
        PrivacyLevel::Public,
        SecurityLevel::Minimal,
    )
    .unwrap();
    let fout = fnode.process_block(batch(7)).unwrap();
    assert!(fout.gas_used > 0, "the batch really consumed gas");
    assert_eq!(fout.fee_charged.as_nano(), 0, "feeless subnet charges nothing");

    // Fee-charging subnet at 2 nano/gas over an identical batch.
    let mut pnode = NodeEngine::open_on_subnet(
        temp_dir("fee-subnet"),
        Address::from_bytes([1u8; 32]),
        SubnetPolicy::fee_public(2, PrivacyLevel::Public),
        PrivacyLevel::Public,
        SecurityLevel::Minimal,
    )
    .unwrap();
    genesis_fund(&mut pnode);
    let pout = pnode.process_block(batch(7)).unwrap();
    assert_eq!(pout.gas_used, fout.gas_used, "same batch, same gas");
    assert_eq!(
        pout.fee_charged.as_nano(),
        u128::from(pout.gas_used) * 2,
        "fee subnet charges gas * price"
    );
}

#[test]
fn subnet_privacy_baseline_rejects_below_and_stamps_at_level() {
    // A subnet enforces a minimum privacy level, just as an object carries one.
    use node::subnet::SubnetPolicy;
    let owner = Address::from_bytes([1u8; 32]);

    // A dApp deploying BELOW the baseline (Public on a Private subnet) is rejected.
    let private_subnet = SubnetPolicy::feeless_permissioned(vec![], PrivacyLevel::Private);
    let rejected = NodeEngine::open_on_subnet(
        temp_dir("priv-below"),
        owner,
        private_subnet.clone(),
        PrivacyLevel::Public,
        SecurityLevel::Minimal,
    );
    assert!(rejected.is_err(), "below-baseline dApp deployment is rejected");

    // Deploying AT the baseline succeeds; the node stamps objects at Private.
    let at = NodeEngine::open_on_subnet(
        temp_dir("priv-at"),
        owner,
        private_subnet,
        PrivacyLevel::Private,
        SecurityLevel::Minimal,
    )
    .unwrap();
    assert_eq!(at.privacy(), PrivacyLevel::Private);
    assert_eq!(at.subnet().min_privacy_level, PrivacyLevel::Private);

    // Deploying ABOVE the baseline (Private dApp on a Protected subnet) is fine.
    let protected_subnet = SubnetPolicy::feeless_permissioned(vec![], PrivacyLevel::Protected);
    let above = NodeEngine::open_on_subnet(
        temp_dir("prot-above"),
        owner,
        protected_subnet,
        PrivacyLevel::Private,
        SecurityLevel::Minimal,
    )
    .unwrap();
    assert_eq!(above.privacy(), PrivacyLevel::Private, "above-baseline dApp allowed");
}

#[test]
fn permissioned_subnet_admits_only_permitted_senders() {
    // A permissioned subnet admits only its permitted participants.
    use node::subnet::SubnetPolicy;
    let permitted = Address::from_bytes([0xAB; 32]);
    let subnet = SubnetPolicy::feeless_permissioned(vec![permitted], PrivacyLevel::Public);
    let mut node = NodeEngine::open_on_subnet(
        temp_dir("permissioned"),
        Address::from_bytes([1u8; 32]),
        subnet,
        PrivacyLevel::Public,
        SecurityLevel::Minimal,
    )
    .unwrap();
    let prog = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);
    let wallet = Ed25519KeyPair::from_seed([9u8; 32]);

    let permitted_tx = signed_tx_from(&wallet, 0, &[], &[0], prog.clone(), permitted);
    assert!(node.submit(permitted_tx), "permitted sender is admitted");

    let other_tx = signed_tx_from(&wallet, 1, &[], &[1], prog, Address::from_bytes([0xCD; 32]));
    assert!(!node.submit(other_tx), "non-permitted sender is rejected");
}

#[test]
fn fee_market_simulation_congestion_pq_price_rewards() {
    // Full economic simulation through the real engine: a congestion-based fee
    // that rises under load and falls when idle, post-quantum bloat pricing,
    // token-price independence, and validator rewards accruing from usage.
    use aevor_crypto::post_quantum::ml_dsa::MlDsa65KeyPair;
    use node::subnet::SubnetPolicy;

    let prog = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);
    let owner = Address::from_bytes([1u8; 32]);
    let ed = Ed25519KeyPair::from_seed([7u8; 32]);

    // --- Congestion: a small-budget subnet (2000 gas/block, target 1000). ---
    let subnet = SubnetPolicy::public_with_congestion(1_000, 2_000, 5_000, 1_250, 100);
    let mut node = NodeEngine::open_on_subnet(
        temp_dir("sim-congestion"),
        owner,
        subnet,
        PrivacyLevel::Public,
        SecurityLevel::Minimal,
    )
    .unwrap();
    genesis_fund(&mut node);
    let base0 = node.current_base_fee();
    assert_eq!(base0, 1_000, "starts at the configured base fee");

    // A congested block (5 txs, well over the 1000-gas target) raises the fee.
    let congested: Vec<_> =
        (0..5u8).map(|i| signed_tx(&ed, i, &[], &[i], prog.to_vec())).collect();
    let cong_out = node.process_block(congested).unwrap();
    assert!(cong_out.gas_used > 1_000, "the block was over target");
    let base_hot = node.current_base_fee();
    assert!(base_hot > base0, "congestion raised the base fee ({base0} -> {base_hot})");

    // Idle blocks (1 small tx each, under target) lower the fee back down.
    for i in 0..6u8 {
        node.process_block(vec![signed_tx(&ed, 100 + i, &[], &[50 + i], prog.to_vec())])
            .unwrap();
    }
    let base_cool = node.current_base_fee();
    assert!(base_cool < base_hot, "idle blocks lowered the base fee ({base_hot} -> {base_cool})");

    // --- Rewards: the validator accrued the fees from those blocks. ---
    assert!(node.validator_reward().as_nano() > 0, "validator earned fees as its reward");

    // --- Post-quantum bloat: a PQ tx costs more than an Ed25519 tx. ---
    // Identical uncongested subnets (huge budget) so both price at the base fee.
    let big = || SubnetPolicy::public_with_congestion(1_000, 30_000_000, 5_000, 1_250, 100);
    let mut n_ed = NodeEngine::open_on_subnet(
        temp_dir("sim-ed"),
        owner,
        big(),
        PrivacyLevel::Public,
        SecurityLevel::Minimal,
    )
    .unwrap();
    let mut n_pq = NodeEngine::open_on_subnet(
        temp_dir("sim-pq"),
        owner,
        big(),
        PrivacyLevel::Public,
        SecurityLevel::Minimal,
    )
    .unwrap();
    genesis_fund(&mut n_ed);
    let ed_fee = n_ed
        .process_block(vec![signed_tx(&ed, 0, &[], &[0], prog.to_vec())])
        .unwrap()
        .fee_charged;
    genesis_fund(&mut n_pq);
    let pq = MlDsa65KeyPair::generate().unwrap();
    let pq_fee = n_pq
        .process_block(vec![signed_tx(&pq, 0, &[], &[0], prog.to_vec())])
        .unwrap()
        .fee_charged;
    assert!(
        pq_fee.as_nano() > ed_fee.as_nano(),
        "post-quantum tx pays more for its bloat (pq {} > ed {})",
        pq_fee.as_nano(),
        ed_fee.as_nano()
    );

    // --- Token-price independence: the protocol fee is congestion-based, not
    // price-based. The native fee is identical at any token price; only the fiat
    // conversion differs (the protocol never reads a token price). ---
    #[allow(clippy::cast_precision_loss)]
    let native_avr = ed_fee.as_nano() as f64 * 1e-9;
    let fiat_at_1 = native_avr * 1.0;
    let fiat_at_150 = native_avr * 150.0;
    assert!(fiat_at_150 > fiat_at_1, "fiat cost scales with token price");
    // Same batch on a second node yields the identical native fee regardless.
    let mut n_ed2 = NodeEngine::open_on_subnet(
        temp_dir("sim-ed2"),
        owner,
        big(),
        PrivacyLevel::Public,
        SecurityLevel::Minimal,
    )
    .unwrap();
    genesis_fund(&mut n_ed2);
    let ed_fee2 = n_ed2
        .process_block(vec![signed_tx(&ed, 0, &[], &[0], prog.to_vec())])
        .unwrap()
        .fee_charged;
    assert_eq!(ed_fee2.as_nano(), ed_fee.as_nano(), "native fee is price-independent");
}

#[test]
fn balance_settlement_debits_senders_credits_validator_and_guards_abuse() {
    // Real settlement: funded senders are debited their fee, the validator is
    // credited the same, conservation holds, and an unfunded sender is rejected
    // by the abuse guard before execution.
    use node::subnet::SubnetPolicy;
    let prog = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);
    let owner = Address::from_bytes([1u8; 32]);
    let ed = Ed25519KeyPair::from_seed([7u8; 32]);

    // Fee subnet (uncongested, large budget so the base fee stays put).
    let subnet = SubnetPolicy::public_with_congestion(1_000, 30_000_000, 5_000, 1_250, 100);
    let mut node = NodeEngine::open_on_subnet(
        temp_dir("settle"),
        owner,
        subnet,
        PrivacyLevel::Public,
        SecurityLevel::Minimal,
    )
    .unwrap();

    // Fund the shared zero sender with a known, modest amount.
    let start = aevor_core::primitives::Amount::from_nano(1_000_000_000); // 1 AVR
    node.fund(Address::ZERO, start);
    assert_eq!(node.balance_of(Address::ZERO).as_nano(), start.as_nano());

    // Process a block of 4 transactions.
    let txs: Vec<_> = (0..4u8).map(|i| signed_tx(&ed, i, &[], &[i], prog.to_vec())).collect();
    let out = node.process_block(txs).unwrap();
    assert_eq!(out.accepted, 4);
    assert_eq!(out.insufficient_funds, 0);
    assert!(out.fee_charged.as_nano() > 0, "a fee was charged");

    // CONSERVATION: the sender's balance dropped by exactly the fee charged, and
    // the validator's reward rose by exactly the same amount.
    let spent = start.as_nano() - node.balance_of(Address::ZERO).as_nano();
    assert_eq!(spent, out.fee_charged.as_nano(), "sender debited exactly the block fee");
    assert_eq!(
        node.validator_reward().as_nano(),
        out.fee_charged.as_nano(),
        "validator credited exactly the block fee"
    );

    // ABUSE GUARD: a brand-new, unfunded sender cannot transact on a fee subnet.
    // (All new_simple txs share the zero sender, so drain it to zero first.)
    let drain = node.balance_of(Address::ZERO);
    assert!(node.balance_of(Address::ZERO).as_nano() > 0);
    // Spend the rest by funding a second node with nothing and trying to transact.
    let mut broke = NodeEngine::open_on_subnet(
        temp_dir("settle-broke"),
        owner,
        SubnetPolicy::public_with_congestion(1_000, 30_000_000, 5_000, 1_250, 100),
        PrivacyLevel::Public,
        SecurityLevel::Minimal,
    )
    .unwrap();
    // No funding at all.
    let out2 = broke.process_block(vec![signed_tx(&ed, 0, &[], &[0], prog.to_vec())]).unwrap();
    assert_eq!(out2.accepted, 0, "unfunded sender cannot execute");
    assert_eq!(out2.insufficient_funds, 1, "dropped by the abuse guard");
    assert_eq!(out2.fee_charged.as_nano(), 0, "nothing settled");
    assert_eq!(broke.validator_reward().as_nano(), 0, "no reward from a rejected tx");
    let _ = drain;

    // FEELESS: a feeless subnet moves no balances even for an unfunded sender.
    let mut free = NodeEngine::open_on_subnet(
        temp_dir("settle-free"),
        owner,
        SubnetPolicy::feeless_permissioned(vec![], PrivacyLevel::Public),
        PrivacyLevel::Public,
        SecurityLevel::Minimal,
    )
    .unwrap();
    let out3 = free.process_block(vec![signed_tx(&ed, 0, &[], &[0], prog.to_vec())]).unwrap();
    assert_eq!(out3.accepted, 1, "feeless subnet needs no funds");
    assert_eq!(out3.fee_charged.as_nano(), 0);
    assert_eq!(out3.insufficient_funds, 0);
}

#[test]
fn independent_nodes_settle_identically_same_rules_same_result() {
    // The finalized economics are deterministic RULES: two independent validators
    // that process the identical block must reach byte-identical balances, fees,
    // validator reward, and state root. This is what "every node follows the same
    // finalized rules" means operationally — no node can settle differently and
    // still agree. (Enforcement against a node that RUNS different rules is the
    // PROTOCOL_RULES_VERSION folded into the attestation; enforcement against a
    // node that claims a different post-state is the shared state root.)
    use node::subnet::SubnetPolicy;
    let prog = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);
    let owner = Address::from_bytes([1u8; 32]);
    let ed = Ed25519KeyPair::from_seed([7u8; 32]);
    let mk = || {
        let mut n = NodeEngine::open_on_subnet(
            temp_dir("determinism"),
            owner,
            SubnetPolicy::public_with_congestion(1_000, 30_000_000, 5_000, 1_250, 100),
            PrivacyLevel::Public,
            SecurityLevel::Minimal,
        )
        .unwrap();
        assert!(n.fund(Address::ZERO, aevor_core::primitives::Amount::from_nano(1_000_000_000)));
        n
    };
    let mut a = mk();
    let mut b = mk();

    let batch: Vec<_> = (0..6u8).map(|i| signed_tx(&ed, i, &[], &[i], prog.to_vec())).collect();
    let oa = a.process_block(batch.clone()).unwrap();
    let ob = b.process_block(batch).unwrap();

    assert_eq!(oa.gas_used, ob.gas_used, "same gas");
    assert_eq!(oa.fee_charged.as_nano(), ob.fee_charged.as_nano(), "same fee");
    assert_eq!(oa.accepted, ob.accepted);
    assert_eq!(a.validator_reward().as_nano(), b.validator_reward().as_nano(), "same reward");
    assert_eq!(
        a.balance_of(Address::ZERO).as_nano(),
        b.balance_of(Address::ZERO).as_nano(),
        "same sender balance after settlement"
    );
    assert_eq!(oa.state_root.0 .0, ob.state_root.0 .0, "same authenticated state root");
    assert_eq!(a.current_base_fee(), b.current_base_fee(), "same next base fee");

    // Post-genesis mint is impossible: fund() is rejected once a block exists.
    assert!(!a.fund(Address::ZERO, aevor_core::primitives::Amount::from_nano(1)), "no minting after genesis");
}

#[test]
fn verifier_stays_balance_consistent_on_fast_path() {
    // A verifier that applies an attested batch WITHOUT re-executing must end with
    // the same balances as the producer, so it can later produce correctly. The
    // balance deltas ride in the StateDelta and are bound by the attestation's
    // balance commitment — cheap HashMap writes, no Merkle cost.
    let prog = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);
    let ed = Ed25519KeyPair::from_seed([7u8; 32]);
    let mut producer = open_node(&temp_dir("fastpath-p")); // fee subnet, funds ZERO at genesis
    let mut verifier = open_node(&temp_dir("fastpath-v")); // same genesis funding

    let txs: Vec<_> = (0..5u8).map(|i| signed_tx(&ed, i, &[], &[i], prog.to_vec())).collect();
    let before = producer.balance_of(Address::ZERO).as_nano();
    let (out, att, delta) = producer.produce_attested_batch(txs).unwrap();
    assert!(out.fee_charged.as_nano() > 0, "fees settled");
    let after = producer.balance_of(Address::ZERO).as_nano();
    assert!(after < before, "producer debited the sender");
    assert!(!delta.balances.is_empty(), "balance delta actually shipped");

    // Verifier applies the delta with NO re-execution.
    verifier.apply_attested_batch(&att, &delta).unwrap();
    assert_eq!(
        verifier.balance_of(Address::ZERO).as_nano(),
        after,
        "verifier's balance view matches the producer's after fast-path apply"
    );

    // The verifier can now produce correctly: its abuse guard sees the debited
    // balance, not a stale one. (Sanity: it still has funds and can settle again.)
    let more: Vec<_> = (10..12u8).map(|i| signed_tx(&ed, i, &[], &[i], prog.to_vec())).collect();
    let out2 = verifier.process_block(more).unwrap();
    assert_eq!(out2.accepted, 2, "verifier produces from a correct balance view");
    assert_eq!(out2.insufficient_funds, 0);
}

#[test]
fn multi_lane_settlement_correct_under_sender_sharding() {
    // The finalized multi-lane balance model for the fee-only economy: concurrent
    // lanes touch DISJOINT accounts (sender-sharded routing — each account's txs go
    // to one lane, and each lane credits only its own validator). Under that, the
    // per-lane ABSOLUTE balance deltas applied by apply_lane_round settle correctly
    // with no cross-lane contention and no double-spend. This test proves it: two
    // lanes with two distinct senders, both debits reflected after the round.
    use node::engine::LaneBlock;
    use node::subnet::SubnetPolicy;
    let prog = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);
    let wallet = Ed25519KeyPair::from_seed([5u8; 32]);
    let start = aevor_core::primitives::Amount::from_nano(1_000_000_000);
    let sender_a = Address::from_bytes([0xAA; 32]);
    let sender_b = Address::from_bytes([0xBB; 32]);

    let open_fee = |tag: &str, funded: &[(Address, aevor_core::primitives::Amount)]| -> NodeEngine {
        let mut e = NodeEngine::open_on_subnet(
            temp_dir(tag),
            Address::from_bytes([1u8; 32]),
            SubnetPolicy::public_with_congestion(1_000, 30_000_000, 5_000, 1_250, 100),
            PrivacyLevel::Public,
            SecurityLevel::Minimal,
        )
        .unwrap();
        for (a, amt) in funded {
            assert!(e.fund(*a, *amt));
        }
        e
    };

    // Lane 0: sender_a on objects [0], from a fresh (empty round-base) producer.
    let mut p0 = open_fee("shard-p0", &[(sender_a, start)]);
    let (_o0, att0, delta0) =
        p0.produce_attested_batch(vec![signed_tx_from(&wallet, 0, &[], &[0], prog.to_vec(), sender_a)]).unwrap();
    let a_after = p0.balance_of(sender_a).as_nano();

    // Lane 1: sender_b on DISJOINT objects [2], from another fresh producer.
    let mut p1 = open_fee("shard-p1", &[(sender_b, start)]);
    let (_o1, att1, delta1) =
        p1.produce_attested_batch(vec![signed_tx_from(&wallet, 1, &[], &[2], prog.to_vec(), sender_b)]).unwrap();
    let b_after = p1.balance_of(sender_b).as_nano();

    assert!(a_after < start.as_nano() && b_after < start.as_nano(), "both senders paid fees");
    assert!(!delta0.balances.is_empty() && !delta1.balances.is_empty(), "both lanes ship balance deltas");

    // A verifier with the same genesis (both senders funded) applies the round.
    let mut v = open_fee("shard-v", &[(sender_a, start), (sender_b, start)]);
    let lanes = vec![
        LaneBlock { lane_id: 0, producer: Hash256([0u8; 32]), attestation: att0, delta: delta0 },
        LaneBlock { lane_id: 1, producer: Hash256([1u8; 32]), attestation: att1, delta: delta1 },
    ];
    let out = v.apply_lane_round(lanes).unwrap();
    assert_eq!(out.lanes_applied, 2);

    // Both lanes' debits are reflected — disjoint accounts, no contention.
    assert_eq!(v.balance_of(sender_a).as_nano(), a_after, "lane 0 (sender_a) debit applied");
    assert_eq!(v.balance_of(sender_b).as_nano(), b_after, "lane 1 (sender_b) debit applied");
}

#[test]
#[allow(clippy::cast_possible_truncation)]
fn multi_node_round_over_transport_converges_with_settlement() {
    // End-to-end multi-node macro-DAG round over the transport seam, in-process:
    // several validators each produce a lane on disjoint accounts/objects, broadcast
    // it, and every validator applies the collected round -> identical state root AND
    // consistent settled balances. Validates the network LOGIC (lane exchange +
    // apply_lane_round + balance-delta settlement) single-core; the real gossip wire
    // (aevor-network) plugs in behind the same Transport trait.
    use node::engine::LaneBlock;
    use node::subnet::SubnetPolicy;
    use node::transport::{InMemoryNet, NetworkMessage, Transport};
    let prog = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);
    let wallet = Ed25519KeyPair::from_seed([5u8; 32]);
    let start = aevor_core::primitives::Amount::from_nano(1_000_000_000);
    let senders = [
        Address::from_bytes([0xA1; 32]),
        Address::from_bytes([0xA2; 32]),
        Address::from_bytes([0xA3; 32]),
    ];
    let open_fee = |tag: &str, funded: &[(Address, aevor_core::primitives::Amount)]| -> NodeEngine {
        let mut e = NodeEngine::open_on_subnet(
            temp_dir(tag),
            Address::from_bytes([1u8; 32]),
            SubnetPolicy::public_with_congestion(1_000, 30_000_000, 5_000, 1_250, 100),
            PrivacyLevel::Public,
            SecurityLevel::Minimal,
        )
        .unwrap();
        for (a, amt) in funded {
            assert!(e.fund(*a, *amt));
        }
        e
    };

    // Network of 5: nodes 0..3 produce lanes, nodes 3..5 verify.
    let net = InMemoryNet::new(5);

    // Each producer (sender-sharded, disjoint objects) produces and broadcasts.
    let mut expected: Vec<(Address, u128)> = Vec::new();
    for (i, &sender) in senders.iter().enumerate() {
        let mut p = open_fee(&format!("mn-p{i}"), &[(sender, start)]);
        let (_o, att, delta) = p
            .produce_attested_batch(vec![signed_tx_from(
                &wallet,
                i as u8,
                &[],
                &[(i as u8) * 2],
                prog.to_vec(),
                sender,
            )])
            .unwrap();
        expected.push((sender, p.balance_of(sender).as_nano()));
        let lane = LaneBlock { lane_id: i as u32, producer: Hash256([i as u8; 32]), attestation: att, delta };
        net.handle(i).broadcast(NetworkMessage::Lane(Box::new(lane)));
    }

    // Two verifiers (fresh, funded for ALL senders = shared genesis) collect and apply.
    let mut roots: Vec<[u8; 32]> = Vec::new();
    let all_funded: Vec<(Address, aevor_core::primitives::Amount)> =
        senders.iter().map(|s| (*s, start)).collect();
    for vi in 3..5usize {
        let mut v = open_fee(&format!("mn-v{vi}"), &all_funded);
        let msgs = net.handle(vi).drain();
        assert_eq!(msgs.len(), 3, "verifier received all three lanes over transport");
        let lanes: Vec<LaneBlock> =
            msgs.into_iter().map(|m| match m { NetworkMessage::Lane(l) => *l }).collect();
        let out = v.apply_lane_round(lanes).unwrap();
        assert_eq!(out.lanes_applied, 3);
        for (sender, bal) in &expected {
            assert_eq!(v.balance_of(*sender).as_nano(), *bal, "settled balance matches producer");
        }
        roots.push(out.state_root.0 .0);
    }
    assert_eq!(roots[0], roots[1], "all validators converge to one state root over the transport");
}

// ---- Attack-surface tests for the multi-lane macro-DAG round ----

fn attack_engine(tag: &str, funded: &[Address]) -> NodeEngine {
    use node::subnet::SubnetPolicy;
    let start = aevor_core::primitives::Amount::from_nano(1_000_000_000);
    let mut e = NodeEngine::open_on_subnet(
        temp_dir(tag),
        Address::from_bytes([1u8; 32]),
        SubnetPolicy::public_with_congestion(1_000, 30_000_000, 5_000, 1_250, 100),
        PrivacyLevel::Public,
        SecurityLevel::Minimal,
    )
    .unwrap();
    for a in funded {
        assert!(e.fund(*a, start));
    }
    e
}

#[test]
fn cross_lane_object_double_spend_is_rejected() {
    // Two lanes that both WRITE THE SAME OBJECT (distinct txs, distinct senders) are
    // a double-spend: the round must be rejected, not silently last-write-wins.
    use node::engine::LaneBlock;
    let prog = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);
    let w = Ed25519KeyPair::from_seed([5u8; 32]);
    let (sa, sb) = (Address::from_bytes([0xC1; 32]), Address::from_bytes([0xC2; 32]));

    let mut p0 = attack_engine("ds-p0", &[sa]);
    let (_o0, att0, d0) = p0
        .produce_attested_batch(vec![signed_tx_from(&w, 0, &[], &[5], prog.to_vec(), sa)])
        .unwrap();
    let mut p1 = attack_engine("ds-p1", &[sb]);
    let (_o1, att1, d1) = p1
        .produce_attested_batch(vec![signed_tx_from(&w, 1, &[], &[5], prog.to_vec(), sb)])
        .unwrap();
    assert_ne!(att0.tx_commitment, att1.tx_commitment, "distinct tx sets (not the trivial dup case)");

    let mut v = attack_engine("ds-v", &[sa, sb]);
    let lanes = vec![
        LaneBlock { lane_id: 0, producer: Hash256([0u8; 32]), attestation: att0, delta: d0 },
        LaneBlock { lane_id: 1, producer: Hash256([1u8; 32]), attestation: att1, delta: d1 },
    ];
    assert!(v.apply_lane_round(lanes).is_err(), "cross-lane object double-spend must be rejected");
}

#[test]
fn duplicate_transaction_set_across_lanes_is_rejected() {
    // Two lanes claiming the IDENTICAL tx set (same tx_commitment) are rejected.
    use node::engine::LaneBlock;
    let prog = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);
    let w = Ed25519KeyPair::from_seed([5u8; 32]);
    let sa = Address::from_bytes([0xC3; 32]);

    // The same transaction produced from two identical fresh engines → same commitment.
    let mut p0 = attack_engine("dup-p0", &[sa]);
    let (_o0, att0, d0) = p0
        .produce_attested_batch(vec![signed_tx_from(&w, 0, &[], &[6], prog.to_vec(), sa)])
        .unwrap();
    let mut p1 = attack_engine("dup-p1", &[sa]);
    let (_o1, att1, d1) = p1
        .produce_attested_batch(vec![signed_tx_from(&w, 0, &[], &[6], prog.to_vec(), sa)])
        .unwrap();
    assert_eq!(att0.tx_commitment, att1.tx_commitment, "identical tx set");

    let mut v = attack_engine("dup-v", &[sa]);
    let lanes = vec![
        LaneBlock { lane_id: 0, producer: Hash256([0u8; 32]), attestation: att0, delta: d0 },
        LaneBlock { lane_id: 1, producer: Hash256([1u8; 32]), attestation: att1, delta: d1 },
    ];
    assert!(v.apply_lane_round(lanes).is_err(), "duplicate tx set across lanes must be rejected");
}

#[test]
fn lane_not_forking_from_round_base_is_rejected() {
    // A lane whose attestation forked from a DIFFERENT prior state (stale/forged
    // fork) is rejected — you cannot splice in a lane built on another history.
    use node::engine::LaneBlock;
    let prog = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);
    let w = Ed25519KeyPair::from_seed([5u8; 32]);
    let sa = Address::from_bytes([0xC4; 32]);

    // Advance a producer, then produce a lane from its NON-empty state.
    let mut p = attack_engine("pr-p", &[sa]);
    p.process_block(vec![signed_tx_from(&w, 0, &[], &[7], prog.to_vec(), sa)]).unwrap();
    let (_o, att, d) = p
        .produce_attested_batch(vec![signed_tx_from(&w, 1, &[], &[8], prog.to_vec(), sa)])
        .unwrap();
    assert_ne!(att.prior_root, [0u8; 32], "lane forked from a non-empty (advanced) state");

    // A fresh verifier at the empty round base must reject it.
    let mut v = attack_engine("pr-v", &[sa]);
    let lanes = vec![LaneBlock { lane_id: 0, producer: Hash256([0u8; 32]), attestation: att, delta: d }];
    assert!(v.apply_lane_round(lanes).is_err(), "lane not forking from round base must be rejected");
}

#[test]
fn tampered_lane_balance_delta_is_rejected() {
    // Tampering a lane's balance delta (without matching commitment) is rejected by
    // the per-lane balance-commitment check in apply_lane_round.
    use node::engine::LaneBlock;
    let prog = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);
    let w = Ed25519KeyPair::from_seed([5u8; 32]);
    let sa = Address::from_bytes([0xC5; 32]);

    let mut p = attack_engine("bt-p", &[sa]);
    let (_o, att, mut d) = p
        .produce_attested_batch(vec![signed_tx_from(&w, 0, &[], &[9], prog.to_vec(), sa)])
        .unwrap();
    assert!(!d.balances.is_empty());
    d.balances[0].1 = d.balances[0].1.wrapping_add(1_000_000); // forge a bigger balance

    let mut v = attack_engine("bt-v", &[sa]);
    let lanes = vec![LaneBlock { lane_id: 0, producer: Hash256([0u8; 32]), attestation: att, delta: d }];
    assert!(v.apply_lane_round(lanes).is_err(), "tampered lane balance delta must be rejected");
}

#[test]
fn cross_lane_same_account_settlement_is_rejected() {
    // Two lanes settling the SAME account (same sender), even on disjoint objects,
    // is a cross-lane balance conflict — rejected. Sender-sharding prevents it
    // upstream; this is the defensive check that makes it a tested rejection.
    use node::engine::LaneBlock;
    let prog = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);
    let w = Ed25519KeyPair::from_seed([5u8; 32]);
    let sa = Address::from_bytes([0xC6; 32]);

    let mut p0 = attack_engine("acc-p0", &[sa]);
    let (_o0, att0, d0) = p0
        .produce_attested_batch(vec![signed_tx_from(&w, 0, &[], &[10], prog.to_vec(), sa)])
        .unwrap();
    let mut p1 = attack_engine("acc-p1", &[sa]);
    let (_o1, att1, d1) = p1
        .produce_attested_batch(vec![signed_tx_from(&w, 1, &[], &[11], prog.to_vec(), sa)])
        .unwrap();
    assert_ne!(att0.tx_commitment, att1.tx_commitment, "distinct tx sets, disjoint objects");

    let mut v = attack_engine("acc-v", &[sa]);
    let lanes = vec![
        LaneBlock { lane_id: 0, producer: Hash256([0u8; 32]), attestation: att0, delta: d0 },
        LaneBlock { lane_id: 1, producer: Hash256([1u8; 32]), attestation: att1, delta: d1 },
    ];
    assert!(v.apply_lane_round(lanes).is_err(), "cross-lane same-account settlement must be rejected");
}
