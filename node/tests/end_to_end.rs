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

use node::engine::{CommitteeMember, NodeEngine, SignedTransaction};

fn obj(n: u8) -> ObjectId {
    ObjectId(Hash256([n; 32]))
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
    NodeEngine::open(
        dir.to_path_buf(),
        Address::from_bytes([1u8; 32]),
        PrivacyLevel::Public,
        SecurityLevel::Minimal,
    )
    .expect("node opens")
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

    // A corrupted delta does not reproduce the attested new root → rejected.
    let dir_v2 = temp_dir("pou-v2");
    let mut v2 = open_node(&dir_v2);
    let mut bad = delta.clone();
    bad[0].1 = vec![0xFFu8; 8];
    assert!(v2.apply_attested_batch(&attestation, &bad).is_err(), "corrupted delta rejected");

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
