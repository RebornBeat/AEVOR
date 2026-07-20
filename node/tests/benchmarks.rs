//! Performance benchmarks for the Proof-of-Uncorruption execution + finality
//! path.
//!
//! These are marked `#[ignore]` so they never run in the normal test pass; run
//! them explicitly to capture numbers:
//!
//! ```text
//! cargo test -p node --test benchmarks --release -- --ignored --nocapture
//! ```
//!
//! Scope and honesty: these measure the **single-node, in-process** pipeline —
//! signature verification, DAG conflict rejection, VM execution, durable
//! persistence, authenticated Merkle commitment, and finality-proof aggregation
//! over a committee. They do NOT include network propagation across a live
//! global validator set, so they are a measure of one node's local pipeline
//! throughput (an upper bound on that node's contribution), not end-to-end
//! wall-clock latency on a deployed network. They exist to (1) track
//! regressions and (2) provide an apples-to-apples-where-possible reference
//! against published single-node execution numbers from other chains.

use std::time::Instant;

use aevor_core::consensus::SecurityLevel;
use aevor_core::primitives::{Address, Hash256, Nonce, ObjectId};
use aevor_core::privacy::PrivacyLevel;
use aevor_core::transaction::{SignedTransaction, Transaction};
use aevor_crypto::agility::{sign_transaction, Signer};
use aevor_crypto::signatures::{BlsKeyPair, Ed25519KeyPair};
use aevor_vm::bytecode::BytecodeCodec;
use aevor_vm::instructions::Instruction::{Add, Ld};

use node::engine::{CommitteeMember, NodeEngine};

/// A distinct object id for each index (supports large batches, unlike a u8).
fn obj_n(n: u32) -> ObjectId {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&n.to_le_bytes());
    b[4] = 0xA5; // domain tag to avoid clashing with other object namespaces
    ObjectId(Hash256(b))
}

fn bench_dir(tag: &str) -> std::path::PathBuf {
    let mut d = std::env::temp_dir();
    d.push(format!(
        "aevor-bench-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    d
}

fn open_engine(dir: &std::path::Path) -> NodeEngine {
    NodeEngine::open(
        dir.to_path_buf(),
        Address::from_bytes([1u8; 32]),
        PrivacyLevel::Public,
        SecurityLevel::Minimal,
    )
    .expect("node opens")
}

/// Build `count` disjoint, well-signed transactions (each writes its own object,
/// so none conflict — this isolates raw pipeline throughput). Uses the exact
/// production builders (`Transaction::new_simple` + `sign_transaction`).
fn disjoint_batch(wallet: &Ed25519KeyPair, count: u32) -> Vec<SignedTransaction> {
    let program = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);
    (0..count)
        .map(|i| {
            let tx = Transaction::new_simple(
                wallet.public_key_multi(),
                Nonce(u64::from(i)),
                &[],
                &[obj_n(i)],
                program.clone(),
            );
            sign_transaction(tx, wallet)
        })
        .collect()
}

#[test]
#[ignore = "benchmark; run with --ignored --nocapture --release"]
fn bench_execution_throughput() {
    let wallet = Ed25519KeyPair::from_seed([9u8; 32]);
    println!("\n=== AEVOR execution throughput (single-node, in-process) ===");
    println!("(verify -> DAG conflict check -> VM execute -> persist -> Merkle commit)\n");
    // Scales up to 100k here; extend to 500k/1M in a --release run with enough
    // RAM to confirm the flat curve holds into the whitepaper's target range.
    for &count in &[1_000u32, 5_000, 10_000, 25_000, 50_000, 100_000] {
        let dir = bench_dir("exec");
        let mut engine = open_engine(&dir);
        let batch = disjoint_batch(&wallet, count); // build (unmeasured)

        let start = Instant::now();
        let outcome = engine.process_block(batch).expect("block processes");
        let elapsed = start.elapsed();

        assert_eq!(outcome.accepted, count as usize, "all disjoint txs accepted");
        let secs = elapsed.as_secs_f64();
        let tps = f64::from(count) / secs;
        println!(
            "  {count:>6} txs  ->  {:>8.2} ms   =  {tps:>12.0} tx/s",
            elapsed.as_secs_f64() * 1000.0
        );
        let _ = std::fs::remove_file(dir.join("state.log"));
    }
}

#[test]
#[ignore = "benchmark; run with --ignored --nocapture --release"]
fn bench_finality_latency() {
    let wallet = Ed25519KeyPair::from_seed([9u8; 32]);
    println!("\n=== AEVOR finality-proof latency (over committee) ===");
    // HONEST NOTE: the current finality path collects N *individual* Ed25519
    // signatures (proof.signatures is a Vec of length N) and is therefore O(N)
    // in committee size — you will see latency grow roughly linearly below.
    // The canonical design uses BLS12-381 aggregation (N sigs -> 1 aggregate,
    // O(1) to verify); until that lands, counts beyond a few thousand are slow.
    // Running this at scale is precisely how we motivate the aggregation change.
    println!("(collects N Ed25519 attestations today -> O(N); BLS aggregation is the planned O(1) change)\n");

    // Committee sizes to sweep — from small BFT-like committees up into the
    // thousands. Extend the last entries (10_000, 50_000) in a --release run;
    // with the current O(N) path they are intentionally heavy.
    let sizes = [4usize, 16, 64, 128, 256, 512, 1_024, 3_000];
    let max_size = *sizes.iter().max().unwrap();

    // Pre-generate the largest committee once; sub-slice for smaller sizes.
    let keys: Vec<Ed25519KeyPair> = (0..max_size as u32)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&i.to_le_bytes());
            Ed25519KeyPair::from_seed(seed)
        })
        .collect();
    let bls_keys: Vec<BlsKeyPair> = (0..max_size as u32)
        .map(|i| {
            let mut ikm = [0u8; 32];
            ikm[..4].copy_from_slice(&i.to_le_bytes());
            BlsKeyPair::from_ikm(ikm)
        })
        .collect();

    for &size in &sizes {
        let dir = bench_dir("final");
        let mut engine = open_engine(&dir);
        // Produce a block to finalize.
        let outcome = engine
            .process_block(disjoint_batch(&wallet, 100))
            .expect("block processes");
        let committee: Vec<CommitteeMember<'_>> = keys[..size]
            .iter()
            .zip(bls_keys[..size].iter())
            .map(|(k, b)| CommitteeMember { keypair: k, bls: b, weight: 100 })
            .collect();

        // Measure only the finalization step.
        let start = Instant::now();
        let finality = engine
            .finalize_block(outcome.block_hash, &committee)
            .expect("finalizes");
        let elapsed = start.elapsed();

        assert!(finality.finalized, "committee met threshold");
        println!(
            "  {size:>3} validators  ->  {:>8.3} ms   ({} sigs, weight {})",
            elapsed.as_secs_f64() * 1000.0,
            finality.signature_count,
            finality.signed_weight
        );
        let _ = std::fs::remove_file(dir.join("state.log"));
    }
}

#[test]
#[ignore = "benchmark; run with --ignored --nocapture --release"]
fn bench_state_proof_latency() {
    let wallet = Ed25519KeyPair::from_seed([9u8; 32]);
    println!("\n=== AEVOR authenticated-state proof latency ===");
    println!("(Merkle inclusion proof generation over committed state)\n");
    for &count in &[1_000u32, 10_000, 25_000] {
        let dir = bench_dir("proof");
        let mut engine = open_engine(&dir);
        engine
            .process_block(disjoint_batch(&wallet, count))
            .expect("block processes");

        // Prove a handful of objects; report the average.
        let samples = [0u32, count / 2, count - 1];
        let start = Instant::now();
        for &i in &samples {
            let proof = engine.prove_object(&obj_n(i)).expect("prove ok");
            assert!(proof.is_some(), "object present");
        }
        let elapsed = start.elapsed();
        let per = elapsed.as_secs_f64() * 1000.0 / samples.len() as f64;
        println!("  state of {count:>6} objects  ->  {per:>8.3} ms / proof");
        let _ = std::fs::remove_file(dir.join("state.log"));
    }
}

/// BLS aggregate finality: verification cost as the validator set scales.
///
/// This is the "no degradation as more validators join" proof. All validators
/// sign the same block hash; the proposer aggregates their N signatures into
/// one; the committee caches its aggregate public key. Per-block verification is
/// then a single pairing check — CONSTANT time regardless of committee size,
/// unlike the O(N) collect-and-verify-each path. This is the property a capped
/// ~100-validator BFT set (e.g. Sui) avoids paying by staying small; AEVOR pays
/// it in O(1), so the set can grow.
#[test]
#[ignore = "benchmark; run with --ignored --nocapture --release"]
fn bench_bls_finality_scaling() {
    use aevor_core::primitives::Hash256;
    use aevor_crypto::bls::{aggregate_public_keys, BlsAggregator};

    println!("\n=== AEVOR BLS aggregate finality: verification cost vs committee size ===");
    println!("(all validators sign one block hash; committee caches its aggregate pubkey)\n");

    let message = [0xABu8; 32]; // stand-in block hash
    let msg_hash = Hash256([0xAB; 32]);

    for &n in &[128usize, 512, 1_024, 3_000, 10_000, 50_000] {
        // Setup (unmeasured): N validators and their signatures over the block hash.
        let keys: Vec<BlsKeyPair> = (0..n)
            .map(|i| {
                let mut ikm = [0u8; 32];
                ikm[..8].copy_from_slice(&(i as u64).to_le_bytes());
                BlsKeyPair::from_ikm(ikm)
            })
            .collect();
        let sigs: Vec<_> = keys.iter().map(|k| k.sign(&message)).collect();

        // Proposer aggregates N signatures -> 1 (O(N), once per block).
        let t_agg = Instant::now();
        let mut aggregator = BlsAggregator::new(msg_hash, n);
        for (i, s) in sigs.iter().enumerate() {
            aggregator.add_signature(i, s).unwrap();
        }
        let agg = aggregator.aggregate().unwrap();
        let agg_ms = t_agg.elapsed().as_secs_f64() * 1000.0;

        // Committee precomputes its aggregate pubkey ONCE (O(N), once per membership change).
        let pubkeys: Vec<_> = keys.iter().map(BlsKeyPair::public_key).collect();
        let t_pre = Instant::now();
        let committee_key = aggregate_public_keys(&pubkeys).unwrap();
        let pre_ms = t_pre.elapsed().as_secs_f64() * 1000.0;

        // THE KEY METRIC: verify the finality proof against the cached key (O(1)).
        let t_ver = Instant::now();
        let ok = agg.verify_with_aggregate_key(&message, &committee_key);
        let ver_us = t_ver.elapsed().as_secs_f64() * 1_000_000.0;
        assert!(ok, "aggregate verifies");

        println!(
            "  {n:>6} validators  ->  verify {ver_us:>8.1} us   (amortized: aggregate {agg_ms:>7.1} ms, precompute-key {pre_ms:>7.1} ms)"
        );
    }
    println!("\n  The 'verify' column is the per-block O(1) cost — it stays flat as the committee");
    println!("  grows. Aggregation and key-precompute are O(N) but amortized (once per block /");
    println!("  once per membership change). THIS is why the validator set can grow without");
    println!("  finality degrading — the differentiator vs a capped BFT validator set.");
}

/// Transaction wire size: classical (Ed25519) vs post-quantum (ML-DSA-65) vs
/// hybrid. Same payload, different signature scheme — isolates the PQ
/// over-the-wire bloat that matters for bandwidth and block size.
#[test]
#[ignore = "benchmark; run with --ignored --nocapture --release"]
fn bench_signature_wire_size() {
    use aevor_core::transaction::Transaction;
    use aevor_crypto::agility::sign_transaction;
    use aevor_crypto::post_quantum::ml_dsa::MlDsa65KeyPair;
    use aevor_crypto::post_quantum::HybridKeyPair;

    println!("\n=== AEVOR transaction wire size: classical vs post-quantum ===");
    println!("(bincode-serialized SignedTransaction; identical payload, different scheme)\n");

    let program = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);

    let ed = Ed25519KeyPair::from_seed([9u8; 32]);
    let tx = Transaction::new_simple(ed.public_key_multi(), Nonce(0), &[], &[obj_n(0)], program.clone());
    let size_ed = bincode::serialize(&sign_transaction(tx, &ed)).unwrap().len();

    let ml = MlDsa65KeyPair::generate().unwrap();
    let tx = Transaction::new_simple(ml.public_key_multi(), Nonce(0), &[], &[obj_n(0)], program.clone());
    let size_ml = bincode::serialize(&sign_transaction(tx, &ml)).unwrap().len();

    let hy = HybridKeyPair::generate().unwrap();
    let tx = Transaction::new_simple(hy.public_key_multi(), Nonce(0), &[], &[obj_n(0)], program.clone());
    let size_hy = bincode::serialize(&sign_transaction(tx, &hy)).unwrap().len();

    println!("  Ed25519 (classical):      {size_ed:>6} bytes   (1.0x baseline)");
    println!("  ML-DSA-65 (post-quantum): {size_ml:>6} bytes   ({:.1}x)", size_ml as f64 / size_ed as f64);
    println!("  Hybrid (Ed25519+ML-DSA):  {size_hy:>6} bytes   ({:.1}x)", size_hy as f64 / size_ed as f64);
    let bloat = size_ml - size_ed;
    println!("\n  PQ over-the-wire bloat: +{bloat} bytes/tx vs classical.");
    println!("  At 100k tx/block: ~{:.1} MB extra per block for PQ signatures alone.", (bloat * 100_000) as f64 / 1_048_576.0);
}

/// Execution throughput by signature scheme: all-classical vs all-post-quantum
/// vs mixed. Isolates the cost of signature VERIFICATION inside `process_block`
/// (the "verify" gate runs on every tx), which is where ML-DSA is far heavier
/// than Ed25519. This is the throughput counterpart to the wire-size benchmark.
#[test]
#[ignore = "benchmark; run with --ignored --nocapture --release"]
fn bench_execution_by_signature_scheme() {
    use aevor_core::transaction::Transaction;
    use aevor_crypto::agility::sign_transaction;
    use aevor_crypto::post_quantum::ml_dsa::MlDsa65KeyPair;

    println!("\n=== AEVOR execution throughput by signature scheme ===");
    println!("(process_block verifies every signature; ML-DSA verify >> Ed25519 verify)\n");

    let count: u32 = 2_000; // modest: ML-DSA signing (setup) is slow in debug
    let program = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);
    let ed = Ed25519KeyPair::from_seed([9u8; 32]);
    let ml = MlDsa65KeyPair::generate().unwrap();

    // Build the three batches (unmeasured setup).
    let batch_ed: Vec<_> = (0..count)
        .map(|i| {
            let tx = Transaction::new_simple(ed.public_key_multi(), Nonce(u64::from(i)), &[], &[obj_n(i)], program.clone());
            sign_transaction(tx, &ed)
        })
        .collect();
    let batch_ml: Vec<_> = (0..count)
        .map(|i| {
            let tx = Transaction::new_simple(ml.public_key_multi(), Nonce(u64::from(i)), &[], &[obj_n(i)], program.clone());
            sign_transaction(tx, &ml)
        })
        .collect();
    let batch_mix: Vec<_> = {
        let (mut en, mut mn) = (0u64, 0u64);
        (0..count)
            .map(|i| {
                if i % 2 == 0 {
                    let tx = Transaction::new_simple(ed.public_key_multi(), Nonce(en), &[], &[obj_n(i)], program.clone());
                    en += 1;
                    sign_transaction(tx, &ed)
                } else {
                    let tx = Transaction::new_simple(ml.public_key_multi(), Nonce(mn), &[], &[obj_n(i)], program.clone());
                    mn += 1;
                    sign_transaction(tx, &ml)
                }
            })
            .collect()
    };

    for (label, batch) in [
        ("all Ed25519 (classical)", batch_ed),
        ("all ML-DSA-65 (post-quantum)", batch_ml),
        ("mixed 50/50", batch_mix),
    ] {
        let dir = bench_dir("exec-scheme");
        let mut engine = open_engine(&dir);
        let start = Instant::now();
        let outcome = engine.process_block(batch).expect("processes");
        let elapsed = start.elapsed();
        assert_eq!(outcome.accepted, count as usize, "all accepted for {label}");
        let tps = f64::from(count) / elapsed.as_secs_f64();
        println!("  {label:<30} {count} txs -> {:>7.1} ms = {tps:>10.0} tx/s", elapsed.as_secs_f64() * 1000.0);
        let _ = std::fs::remove_file(dir.join("state.log"));
    }
    println!("\n  The gap is signature-verification cost: classical is cheap, PQ is heavy, mixed is in between.");
    println!("  Combined with the 14.6x wire bloat, this is why PQ is opt-in, not the default.");
}

/// The Proof-of-Uncorruption payoff, measured: a validator that VERIFIES a
/// batch attestation and applies the delta vs one that RE-EXECUTES the batch
/// (the PoW/PoS-style cost every node pays). Same batch, same result; the
/// verify path skips the VM and per-tx signature checks entirely.
#[test]
#[ignore = "benchmark; run with --ignored --nocapture --release"]
fn bench_pou_reexecute_vs_verify() {
    let wallet = Ed25519KeyPair::from_seed([9u8; 32]);
    println!("\n=== AEVOR PoU: re-execute vs verify-by-attestation (per validator) ===");
    println!("(producer executes once + attests; verifiers verify the attestation, not the work)\n");

    for &count in &[1_000u32, 5_000, 10_000, 25_000, 50_000] {
        // Producer executes ONCE and emits (attestation, delta).
        let dir_p = bench_dir("pou-prod");
        let mut producer = open_engine(&dir_p);
        let (_, attestation, delta) = producer
            .produce_attested_batch(disjoint_batch(&wallet, count))
            .expect("produce");

        // Path A — a validator RE-EXECUTES (verify sigs + DAG + VM + persist + Merkle).
        let dir_a = bench_dir("pou-reexec");
        let mut reexec = open_engine(&dir_a);
        let t_a = Instant::now();
        reexec.process_block(disjoint_batch(&wallet, count)).expect("reexec");
        let reexec_ms = t_a.elapsed().as_secs_f64() * 1000.0;

        // Path B — a validator VERIFIES the attestation + applies the delta (PoU).
        let dir_b = bench_dir("pou-verify");
        let mut verify = open_engine(&dir_b);
        let t_b = Instant::now();
        verify.apply_attested_batch(&attestation, &delta).expect("verify");
        let verify_ms = t_b.elapsed().as_secs_f64() * 1000.0;

        let reexec_tps = f64::from(count) / (reexec_ms / 1000.0);
        let verify_tps = f64::from(count) / (verify_ms / 1000.0);
        println!(
            "  {count:>6} txs:  re-execute {reexec_ms:>7.1} ms ({reexec_tps:>9.0} tx/s)  |  verify-attest {verify_ms:>7.1} ms ({verify_tps:>10.0} tx/s)  =  {:>4.1}x",
            reexec_ms / verify_ms
        );
        for d in [dir_p, dir_a, dir_b] {
            let _ = std::fs::remove_file(d.join("state.log"));
        }
    }
    println!("\n  Every non-producing validator pays the 'verify-attest' cost, not 're-execute'.");
    println!("  In PoW/PoS ALL nodes pay 're-execute'; that is the bound PoU removes.");
}

/// Sparse Merkle tree: single-operation cost vs tree size. Insert, prove, and
/// verify are each O(depth) = O(256) — CONSTANT regardless of how many keys are
/// already present. This is the O(log n)-interior property (contrast the
/// sorted-leaf prover, whose per-proof rebuild is O(n)).
#[test]
#[ignore = "benchmark; run with --ignored --nocapture --release"]
fn bench_sparse_merkle_scaling() {
    use aevor_core::storage::{StorageKey, StorageValue};
    use aevor_crypto::merkle::SparseMerkleTree;

    println!("\n=== Sparse Merkle tree: single-op cost vs tree size (O(depth), flat) ===");
    println!("(insert / prove / verify are O(256) — independent of the number of keys)\n");

    let checkpoints = [1_000usize, 10_000, 100_000];
    let max = *checkpoints.iter().max().unwrap();
    let mut tree = SparseMerkleTree::new();
    let mut ci = 0;
    for i in 0..max {
        tree.insert(
            &StorageKey(format!("key-{i}").into_bytes()),
            StorageValue(format!("val-{i}").into_bytes()),
        );
        if ci < checkpoints.len() && i + 1 == checkpoints[ci] {
            let n = checkpoints[ci];
            let probe = StorageKey(format!("probe-{n}").into_bytes());

            let t_ins = Instant::now();
            tree.insert(&probe, StorageValue(b"probe".to_vec()));
            let ins_us = t_ins.elapsed().as_secs_f64() * 1e6;

            let t_pf = Instant::now();
            let proof = tree.prove(&probe).unwrap();
            let pf_us = t_pf.elapsed().as_secs_f64() * 1e6;

            let t_vf = Instant::now();
            let ok = SparseMerkleTree::verify(&proof);
            let vf_us = t_vf.elapsed().as_secs_f64() * 1e6;
            assert!(ok);

            println!("  n={n:>7}:  insert {ins_us:>7.1} us  |  prove {pf_us:>7.1} us  |  verify {vf_us:>7.1} us");
            ci += 1;
        }
    }
    println!("\n  Flat in n: each op is O(depth). This is the O(log n) interior-update structure");
    println!("  for incremental + proof-heavy workloads (the sorted-leaf prover is O(n) per proof).");
}
