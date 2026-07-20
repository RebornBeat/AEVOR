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
use aevor_crypto::signatures::Ed25519KeyPair;
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

    for &size in &sizes {
        let dir = bench_dir("final");
        let mut engine = open_engine(&dir);
        // Produce a block to finalize.
        let outcome = engine
            .process_block(disjoint_batch(&wallet, 100))
            .expect("block processes");
        let committee: Vec<CommitteeMember<'_>> = keys[..size]
            .iter()
            .map(|k| CommitteeMember { keypair: k, weight: 100 })
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
    use aevor_crypto::signatures::BlsKeyPair;

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
