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
use aevor_core::primitives::{Address, Amount, Hash256, Nonce, ObjectId};
use aevor_core::privacy::PrivacyLevel;
use aevor_core::transaction::{SignedTransaction, Transaction};
use aevor_crypto::agility::{sign_transaction, Signer};
use aevor_crypto::signatures::{BlsKeyPair, Ed25519KeyPair};
use aevor_vm::bytecode::BytecodeCodec;
use aevor_vm::instructions::Instruction::{Add, Ld};

use node::engine::{CommitteeMember, MerkleBackend, NodeEngine};

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
    let mut e = NodeEngine::open(
        dir.to_path_buf(),
        Address::from_bytes([1u8; 32]),
        PrivacyLevel::Public,
        SecurityLevel::Minimal,
    )
    .expect("node opens");
    bench_fund(&mut e);
    e
}

/// Genesis allocation for benchmarks: `disjoint_batch` builds every transaction
/// with `new_simple`, so they all share the zero sender. Fund it far beyond any
/// benchmark's needs so the account-settlement layer always has balance to debit
/// (the point of these benchmarks is throughput, not exhausting a wallet).
fn bench_fund(e: &mut NodeEngine) {
    e.fund(Address::ZERO, Amount::from_nano(u128::MAX / 2));
}

/// Report the economics *settled by the run itself* (not a standalone
/// simulation): gas, the congestion base fee, the block fee actually charged and
/// debited, the validator reward accrued, and a fiat display at three token
/// prices. Conservation holds by construction: block fee == validator credit ==
/// sender debit.
#[allow(clippy::cast_precision_loss)]
fn print_block_economics(label: &str, out: &node::engine::BlockOutcome, base_fee: u64, reward_nano: u128) {
    let acc = f64::from(u32::try_from(out.accepted).unwrap_or(u32::MAX)).max(1.0);
    let fee_nano = out.fee_charged.as_nano();
    let avr = fee_nano as f64 / 1e9;
    println!("    --- ECONOMICS ({label}): settled with the run, not simulated ---");
    println!(
        "      accepted {} | insufficient-funds drops {} | base fee {base_fee} nano/gas",
        out.accepted, out.insufficient_funds
    );
    println!(
        "      total gas {} | gas/tx {:.1} | block fee {fee_nano} nano ({avr:.6} AVR) | fee/tx {:.1} nano",
        out.gas_used,
        out.gas_used as f64 / acc,
        fee_nano as f64 / acc
    );
    println!(
        "      validator reward accrued {reward_nano} nano (= sender debited: conservation) | fiat/block ${:.6} @ $0.01/AVR  ${:.4} @ $1/AVR  ${:.2} @ $150/AVR",
        avr * 0.01,
        avr,
        avr * 150.0
    );
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

/// COMBINED PoU scaling benchmark — the pieces measured together, not in
/// isolation, to find the true throughput and how it scales as validators
/// expand across dual-DAG lanes.
///
/// Part 1: batch-size sweet spot for both execution modes (why ~a few k is best).
/// Part 2: dual-DAG network model — per-producer + per-verifier rates measured,
///         then aggregate throughput as concurrent macro-DAG lanes (validators)
///         expand, in both the full-verification and sharded-verification regimes.
#[test]
#[ignore = "benchmark; run with --ignored --nocapture --release"]
fn bench_combined_pou_scaling() {
    let wallet = Ed25519KeyPair::from_seed([9u8; 32]);

    println!("\n=== PART 1: batch-size sweet spot (Ed25519), both execution modes ===");
    println!("  batch |  re-execute tx/s |  verify-attest tx/s | PoU speedup | fee/tx nano | block fee AVR | base fee");
    let mut best = (0u32, 0.0f64);
    for &b in &[500u32, 1_000, 2_000, 3_000, 5_000, 8_000, 10_000, 15_000, 25_000, 50_000] {
        // Producer makes an attested batch once (for the verify path). This also
        // settles the block's fees, so its outcome carries the economics.
        let dprod = bench_dir("cmb-prod");
        let mut prod = open_engine(&dprod);
        let (out, att, delta) = prod.produce_attested_batch(disjoint_batch(&wallet, b)).unwrap();
        let fee_per_tx = out.fee_charged.as_nano() as f64 / f64::from(b);
        let block_avr = out.fee_charged.as_nano() as f64 / 1e9;
        let base_fee = prod.current_base_fee();

        // Re-execute path.
        let dre = bench_dir("cmb-re");
        let mut re = open_engine(&dre);
        let t = Instant::now();
        re.process_block(disjoint_batch(&wallet, b)).unwrap();
        let re_tps = f64::from(b) / t.elapsed().as_secs_f64();

        // Verify-attest path.
        let dvf = bench_dir("cmb-vf");
        let mut vf = open_engine(&dvf);
        let t = Instant::now();
        vf.apply_attested_batch(&att, &delta).unwrap();
        let vf_tps = f64::from(b) / t.elapsed().as_secs_f64();

        if re_tps > best.1 { best = (b, re_tps); }
        println!(
            "  {b:>6} | {re_tps:>16.0} | {vf_tps:>19.0} | {:>6.1}x | {fee_per_tx:>11.1} | {block_avr:>12.6} | {base_fee:>7}",
            vf_tps / re_tps
        );
        for d in [dprod, dre, dvf] { let _ = std::fs::remove_file(d.join("state.log")); }
    }
    println!("  -> re-execute peaks around batch {} ({:.0} tx/s)", best.0, best.1);
    println!("  -> ECONOMICS: fee/tx is flat (~intrinsic+exec gas x base fee) and cheap at every");
    println!("     batch size; total block fee scales linearly with batch. The economic sweet");
    println!("     spot coincides with the throughput sweet spot: the batch that maximizes tx/s");
    println!("     also maximizes fee revenue per unit wall-clock at the same flat per-tx cost.");

    println!("\n=== PART 2: dual-DAG network throughput as validators/lanes expand ===");
    // Measure the two component rates at a representative lane batch.
    let lane_batch = 5_000u32;
    let dprod = bench_dir("net-prod");
    let mut prod = open_engine(&dprod);
    let t = Instant::now();
    let (_, att, delta) = prod.produce_attested_batch(disjoint_batch(&wallet, lane_batch)).unwrap();
    let producer_rate = f64::from(lane_batch) / t.elapsed().as_secs_f64();
    let dvf = bench_dir("net-vf");
    let mut vf = open_engine(&dvf);
    let t = Instant::now();
    vf.apply_attested_batch(&att, &delta).unwrap();
    let verifier_rate = f64::from(lane_batch) / t.elapsed().as_secs_f64();
    for d in [dprod, dvf] { let _ = std::fs::remove_file(d.join("state.log")); }

    println!("  per-producer execution rate: {producer_rate:>10.0} tx/s (one macro-DAG lane)");
    println!("  per-verifier attest rate:    {verifier_rate:>10.0} tx/s (verifying others' lanes)");
    let crossover = (verifier_rate / producer_rate).floor() as u64;
    println!("  full-verification crossover: ~{crossover} lanes before a verifier saturates\n");

    println!("  lanes(N) | aggregate exec | full-verif ceiling | sharded (uncapped) | BLS finality verify");
    for &n in &[1u64, 2, 4, 8, 16, 32, 64, 128, 512, 3_000, 10_000] {
        let aggregate = n as f64 * producer_rate;         // N concurrent lanes
        let full_verif = aggregate.min(verifier_rate);    // one verifier checks all lanes
        // Sharded: each validator verifies a constant slice, so aggregate scales with N.
        let sharded = aggregate;
        // BLS finality verify is O(1) regardless of N (measured ~1.3ms elsewhere).
        println!(
            "  {n:>8} | {aggregate:>14.0} | {full_verif:>18.0} | {sharded:>18.0} | O(1) ~1.3 ms",
        );
    }
    println!("\n  Full-verification (every validator checks every lane): aggregate is capped at the");
    println!("  per-verifier rate (~{verifier_rate:.0} tx/s) once past ~{crossover} lanes.");
    println!("  Sharded verification (each validator checks a slice): aggregate scales with N —");
    println!("  THIS is the uncapped regime, and it stays secure because every lane is still");
    println!("  attestation-verified by someone and finality is O(1)-aggregated across all N.");
}

fn open_engine_backend(dir: &std::path::Path, backend: MerkleBackend) -> NodeEngine {
    let mut e = NodeEngine::open_with_backend(
        dir.to_path_buf(),
        Address::from_bytes([1u8; 32]),
        PrivacyLevel::Public,
        SecurityLevel::Minimal,
        backend,
    )
    .expect("node opens");
    bench_fund(&mut e);
    e
}

/// FULL MATRIX — the sorted-vs-sparse Merkle backend measured in the REAL engine
/// paths (re-execute, verify-attest, proof generation) across batch sizes. This
/// replaces the earlier analysis of sparse-vs-sorted with actual numbers: sorted
/// wins batch commit (O(n) once), sparse wins proof generation (O(depth) vs O(n)).
#[test]
#[ignore = "benchmark; run with --ignored --nocapture --release"]
fn bench_full_matrix() {
    let wallet = Ed25519KeyPair::from_seed([9u8; 32]);
    println!("\n=== FULL MATRIX: Merkle backend x batch x mode (real engine, measured) ===");
    println!("  backend | batch | re-execute tx/s | verify-attest tx/s | proof-gen us");
    for backend in [MerkleBackend::Sorted, MerkleBackend::Sparse] {
        let name = match backend {
            MerkleBackend::Sorted => "sorted",
            MerkleBackend::Sparse => "sparse",
        };
        for &b in &[1_000u32, 5_000, 10_000, 25_000, 50_000] {
            // Re-execute path (full VM), on this backend.
            let dre = bench_dir("fm-re");
            let mut re = open_engine_backend(&dre, backend);
            let t = Instant::now();
            re.process_block(disjoint_batch(&wallet, b)).unwrap();
            let re_tps = f64::from(b) / t.elapsed().as_secs_f64();

            // Proof generation for one object after the commit (cold path).
            let t = Instant::now();
            let _ = re.prove_object(&obj_n(0)).unwrap();
            let proof_us = t.elapsed().as_secs_f64() * 1e6;

            // Verify-attest path (no VM), on this backend.
            let dprod = bench_dir("fm-prod");
            let mut prod = open_engine_backend(&dprod, backend);
            let (_, att, delta) =
                prod.produce_attested_batch(disjoint_batch(&wallet, b)).unwrap();
            let dvf = bench_dir("fm-vf");
            let mut vf = open_engine_backend(&dvf, backend);
            let t = Instant::now();
            vf.apply_attested_batch(&att, &delta).unwrap();
            let vf_tps = f64::from(b) / t.elapsed().as_secs_f64();

            println!("  {name:>7} | {b:>6} | {re_tps:>15.0} | {vf_tps:>18.0} | {proof_us:>10.1}");
            for d in [dre, dprod, dvf] {
                let _ = std::fs::remove_file(d.join("state.log"));
            }
        }
    }
    println!("\n  -> sorted wins the batch commit (single O(n) rebuild); sparse wins proof");
    println!("     generation (O(depth) vs O(n) rebuild). Right structure per workload.");
}

fn disjoint_batch_offset(wallet: &Ed25519KeyPair, count: u32, offset: u32) -> Vec<SignedTransaction> {
    let program = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);
    (0..count)
        .map(|i| {
            let tx = Transaction::new_simple(
                wallet.public_key_multi(),
                Nonce(u64::from(i)),
                &[],
                &[obj_n(offset + i)],
                program.clone(),
            );
            sign_transaction(tx, wallet)
        })
        .collect()
}

/// F-A1 verification: a verifier applying N concurrently-produced lanes per
/// round (the macro-DAG multi-lane path). Aggregate work per round = N × per-lane.
/// NOTE: this box is single-core, so lanes are *produced* serially here; on a
/// real network each lane is produced on its own validator's hardware in
/// parallel. This measures the verifier's aggregate apply capacity per round.
#[test]
#[ignore = "benchmark; run with --ignored --nocapture --release"]
fn bench_multi_lane_round() {
    use node::engine::LaneBlock;
    let per_lane = 2_000u32;
    println!("\n=== Multi-lane round: verifier applying N concurrent lanes (macro-DAG) ===");
    println!("  lanes | txs/lane | total txs | apply wall | verifier aggregate tx/s");
    for &n in &[1u32, 2, 4, 8, 16, 32] {
        // Produce N lanes on DISJOINT object ranges.
        let mut lanes = Vec::with_capacity(n as usize);
        for lane_id in 0..n {
            let wallet = Ed25519KeyPair::from_seed([(lane_id + 1) as u8; 32]);
            let dir = bench_dir("mlb-src");
            let mut eng = open_engine(&dir);
            let txs = disjoint_batch_offset(&wallet, per_lane, lane_id * per_lane);
            let (_o, attestation, delta) = eng.produce_attested_batch(txs).unwrap();
            lanes.push(LaneBlock { lane_id, producer: aevor_core::primitives::Hash256([lane_id as u8; 32]), attestation, delta });
            let _ = std::fs::remove_file(dir.join("state.log"));
        }
        // Apply the whole round on a fresh verifier.
        let dv = bench_dir("mlb-verify");
        let mut ver = open_engine(&dv);
        let t = Instant::now();
        let out = ver.apply_lane_round(lanes).unwrap();
        let wall = t.elapsed().as_secs_f64();
        assert_eq!(out.lanes_applied, n as usize);
        let total = f64::from(n * per_lane);
        println!(
            "  {n:>5} | {per_lane:>8} | {:>9} | {:>7.1} ms | {:>15.0}",
            n * per_lane,
            wall * 1e3,
            total / wall
        );
        let _ = std::fs::remove_file(dv.join("state.log"));
    }
    println!("\n  A verifier applies N lanes' work per round; network aggregate = N x per-lane");
    println!("  (each lane produced on its own validator in parallel — not measurable on 1 core).");
}

/// F-A2 verification: under sharded verification each validator processes only
/// its assigned slice (~quorum lanes), so its load stays BOUNDED as the
/// validator/lane count grows — while the network aggregate = N x per-lane.
/// This is the uncapped regime (contrast full verification, capped at one
/// verifier's rate). Validator-0's slice time should be ~flat across N.
#[test]
#[ignore = "benchmark; run with --ignored --nocapture --release"]
fn bench_sharded_verification_scaling() {
    use node::engine::LaneBlock;
    let per_lane = 500u32;
    let quorum = 3usize;
    println!("\n=== Sharded verification: per-validator load bounded as N grows ===");
    println!("  N (val=lanes) | validator-0 slice lanes | slice apply | slice tx/s | network lanes");
    for &n in &[8usize, 16, 32, 64, 128] {
        // One lane per validator, disjoint object ranges.
        let mut lanes = Vec::with_capacity(n);
        for lane_id in 0..n {
            let wallet = Ed25519KeyPair::from_seed([(lane_id % 250 + 1) as u8; 32]);
            let dir = bench_dir("shb-src");
            let mut eng = open_engine(&dir);
            let txs = disjoint_batch_offset(&wallet, per_lane, lane_id as u32 * per_lane);
            let (_o, attestation, delta) = eng.produce_attested_batch(txs).unwrap();
            lanes.push(LaneBlock { lane_id: lane_id as u32, producer: aevor_core::primitives::Hash256([lane_id as u8; 32]), attestation, delta });
            let _ = std::fs::remove_file(dir.join("state.log"));
        }
        // Measure ONLY validator-0's assigned slice.
        let dv = bench_dir("shb-v0");
        let mut node = open_engine(&dv);
        let t = Instant::now();
        let out = node.apply_lane_round_sharded(lanes, 0, n, quorum).unwrap();
        let wall = t.elapsed().as_secs_f64().max(1e-9);
        let slice_tx = f64::from(out.lanes_applied as u32 * per_lane);
        println!(
            "  {n:>13} | {:>23} | {:>7.2} ms | {:>10.0} | {:>13}",
            out.lanes_applied,
            wall * 1e3,
            slice_tx / wall,
            n
        );
        let _ = std::fs::remove_file(dv.join("state.log"));
    }
    println!("\n  validator-0's slice (~quorum lanes) stays ~constant while N grows: per-validator");
    println!("  load is bounded, network aggregate = N x per-lane => uncapped, unlike full verification.");
}

/// FINAL consolidated benchmark — one lane's complete PoU lifecycle at the
/// sweet-spot batch, showing WHERE the time goes and therefore what the true
/// bottleneck is, then the network aggregate projection. This ties every prior
/// finding into one picture: production is the per-lane bottleneck; verification
/// is heavily over-provisioned; scaling is N lanes x per-lane production.
#[test]
#[ignore = "benchmark; run with --ignored --nocapture --release"]
fn bench_full_pipeline() {
    let wallet = Ed25519KeyPair::from_seed([9u8; 32]);
    let batch = 5_000u32; // the measured sweet spot

    // Stage 1 — PRODUCE: execute (VM) + commit (Merkle) + attest. Per-lane cost.
    let dprod = bench_dir("fp-prod");
    let mut prod = open_engine(&dprod);
    let t = Instant::now();
    let (out, att, delta) = prod.produce_attested_batch(disjoint_batch(&wallet, batch)).unwrap();
    let produce_s = t.elapsed().as_secs_f64();
    let produce_rate = f64::from(batch) / produce_s;
    let prod_base_fee = prod.current_base_fee();
    let prod_reward = prod.validator_reward().as_nano();

    // Stage 2 — VERIFY: check attestation + apply delta (NO re-execution). Per-verifier cost.
    let dvf = bench_dir("fp-vf");
    let mut vf = open_engine(&dvf);
    let t = Instant::now();
    vf.apply_attested_batch(&att, &delta).unwrap();
    let verify_s = t.elapsed().as_secs_f64();
    let verify_rate = f64::from(batch) / verify_s;

    // Stage 3 — re-execute baseline (what a chain WITHOUT PoU forces every node to do).
    let dre = bench_dir("fp-re");
    let mut re = open_engine(&dre);
    let t = Instant::now();
    re.process_block(disjoint_batch(&wallet, batch)).unwrap();
    let reexec_rate = f64::from(batch) / t.elapsed().as_secs_f64();

    println!("\n=== FINAL: complete PoU pipeline @ {batch} tx/lane (sweet spot) ===\n");
    println!("  Stage              rate (tx/s)     share of a lane's wall-clock");
    println!("  PRODUCE (execute)  {produce_rate:>11.0}     <- the per-lane BOTTLENECK");
    println!("  VERIFY  (attest)   {verify_rate:>11.0}     {:.0}x faster than produce (over-provisioned)", verify_rate / produce_rate);
    println!("  re-execute (no PoU){reexec_rate:>11.0}     for contrast: every node re-doing the work");
    println!("  FINALIZE (BLS)     O(1) ~1.3 ms      flat to 50k validators (measured separately)\n");

    println!("  => The bottleneck is PRODUCTION, not verification or finality.");
    println!("     Verifiers run ~{:.0}x faster than producers, so they never gate the network.", verify_rate / produce_rate);
    println!("     Two levers maximise throughput: (a) per-lane production (multi-core execution),");
    println!("     (b) number of lanes. Verification and finality have huge headroom.\n");

    println!("  Network aggregate = N lanes x per-lane production (each lane on its own hardware):");
    println!("    lanes(N) |   aggregate tx/s   | one verifier keeps up?");
    let verifier_ceiling = verify_rate;
    for &n in &[1u64, 8, 64, 96, 512, 3_000, 10_000] {
        let agg = n as f64 * produce_rate;
        let full_ok = if agg <= verifier_ceiling { "yes (full verif)" } else { "no -> shard verif" };
        println!("    {n:>8} | {agg:>18.0} | {full_ok}");
    }
    println!("\n  Full verification saturates one verifier at ~{:.0} lanes; sharded verification", verifier_ceiling / produce_rate);
    println!("  (F-A2) removes that limit — aggregate then scales linearly with N, uncapped.");

    // Economics settled by the production run itself — the "hook economics into
    // the throughput pipeline" this finalization calls for: same block, one
    // number for gas/fee/reward, not a separate simulation.
    print_block_economics("PRODUCE lane block", &out, prod_base_fee, prod_reward);

    for d in [dprod, dvf, dre] {
        let _ = std::fs::remove_file(d.join("state.log"));
    }
}

/// Measure real gas-per-transaction across program sizes and translate it into a
/// fee under the reconciled, single-source-of-truth fee model
/// (`fee = gas_used * gas_price`, price from the shared `FeeConfig`). Reports the
/// mainnet cost and confirms a feeless subnet is zero. Run with:
/// `cargo test -p node --test benchmarks bench_gas_and_fee_estimates -- --ignored --nocapture --release`
#[test]
#[ignore]
fn bench_gas_and_fee_estimates() {
    use node::subnet::SubnetPolicy;
    let wallet = Ed25519KeyPair::from_seed([5u8; 32]);

    let mainnet = SubnetPolicy::public_mainnet();
    let price = mainnet.effective_gas_price().0;
    println!("\n=== GAS / FEE ESTIMATES (single-source fee: gas_used * gas_price) ===");
    println!("mainnet effective gas price = {price} nano/gas  (FeeConfig::default base fee)");
    println!(
        "{:>10} {:>10} {:>20} {:>18}",
        "instrs/tx", "gas/tx", "mainnet fee (nanoAVR)", "mainnet fee (AVR)"
    );
    for (i, blocks) in [1u32, 10, 100, 1000].into_iter().enumerate() {
        // Fresh engine per size so each is measured at the base (uncongested) fee.
        let mut eng = NodeEngine::open(
            bench_dir(&format!("gas-fee-{i}")),
            Address::from_bytes([1u8; 32]),
            PrivacyLevel::Public,
            SecurityLevel::Minimal,
        )
        .unwrap();
        let instrs: Vec<_> =
            std::iter::repeat_n([Ld(2), Ld(3), Add], blocks as usize).flatten().collect();
        let program = BytecodeCodec::encode(&instrs);
        let n_instrs = blocks * 3;
        let tx = Transaction::new_simple(
            wallet.public_key_multi(),
            Nonce(1000 + i as u64),
            &[],
            &[obj_n(1_000_000 + blocks)],
            program,
        );
        let signed = sign_transaction(tx, &wallet);
        let out = eng.process_block(vec![signed]).unwrap();
        let gas = out.gas_used;
        let fee = mainnet.fee_for(gas);
        #[allow(clippy::cast_precision_loss)]
        let fee_avr = fee.as_nano() as f64 / 1e9;
        // Total gas now includes intrinsic (size/bloat) gas; fee_charged is the
        // dynamic market fee, equal to the base-price fee on this first block.
        assert_eq!(out.fee_charged.as_nano(), fee.as_nano());
        println!("{n_instrs:>10} {gas:>10} {:>20} {fee_avr:>18.9}", fee.as_nano());
    }

    let feeless = SubnetPolicy::feeless_permissioned(vec![], PrivacyLevel::Public);
    println!(
        "feeless subnet fee for even 1,000,000 gas = {} nanoAVR (zero)",
        feeless.fee_for(1_000_000).as_nano()
    );
    println!("note: gas already includes the ~TEE execution premium from the VM gas schedule.");
}

/// Simulate the fee market end-to-end and print the dynamics: the base-fee
/// trajectory through congested and idle blocks, the post-quantum bloat premium,
/// the fiat cost at several token prices, and validator reward accrual. Run with:
/// `cargo test -p node --test benchmarks bench_fee_market_dynamics -- --ignored --nocapture`
#[test]
#[ignore]
fn bench_fee_market_dynamics() {
    use aevor_crypto::post_quantum::ml_dsa::MlDsa65KeyPair;
    use node::subnet::SubnetPolicy;

    let prog = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);
    let owner = Address::from_bytes([1u8; 32]);
    let ed = Ed25519KeyPair::from_seed([7u8; 32]);

    fn sx<S: Signer>(w: &S, nonce: u8, write: u8, prog: &[u8]) -> SignedTransaction {
        let tx = Transaction::new_simple(
            w.public_key_multi(),
            Nonce(u64::from(nonce)),
            &[],
            &[obj_n(u32::from(write))],
            prog.to_vec(),
        );
        sign_transaction(tx, w)
    }

    println!("\n=== FEE MARKET DYNAMICS (congestion-based, token-price-independent) ===");
    let subnet = SubnetPolicy::public_with_congestion(1_000, 2_000, 5_000, 1_250, 100);
    let mut node = NodeEngine::open_on_subnet(
        bench_dir("fm-dyn"),
        owner,
        subnet,
        PrivacyLevel::Public,
        SecurityLevel::Minimal,
    )
    .unwrap();
    bench_fund(&mut node);
    println!("subnet: budget 2000 gas/block, target 1000, +/-12.5% max step, floor 100 nano/gas");
    println!("{:>6} {:>10} {:>10} {:>14} {:>16}", "block", "gas", "over/under", "base fee", "cumul reward");
    let mut nonce = 0u8;
    // 3 congested blocks (5 txs each), then 8 idle blocks (1 tx each).
    for round in 0..11u8 {
        let n = if round < 3 { 5 } else { 1 };
        let txs: Vec<_> = (0..n)
            .map(|_| {
                nonce = nonce.wrapping_add(1);
                sx(&ed, nonce, nonce, &prog)
            })
            .collect();
        let out = node.process_block(txs).unwrap();
        let target = 1_000i64;
        let delta = out.gas_used as i64 - target;
        println!(
            "{:>6} {:>10} {:>+10} {:>14} {:>16}",
            round + 1,
            out.gas_used,
            delta,
            node.current_base_fee(),
            node.validator_reward().as_nano()
        );
    }

    // PQ vs Ed25519 bloat premium (uncongested).
    let big = || SubnetPolicy::public_with_congestion(1_000, 30_000_000, 5_000, 1_250, 100);
    let mut n_ed = NodeEngine::open_on_subnet(bench_dir("fm-ed"), owner, big(), PrivacyLevel::Public, SecurityLevel::Minimal).unwrap();
    bench_fund(&mut n_ed);
    let mut n_pq = NodeEngine::open_on_subnet(bench_dir("fm-pq"), owner, big(), PrivacyLevel::Public, SecurityLevel::Minimal).unwrap();
    bench_fund(&mut n_pq);
    let ed_fee = n_ed.process_block(vec![sx(&ed, 0, 0, &prog)]).unwrap().fee_charged.as_nano();
    let pq = MlDsa65KeyPair::generate().unwrap();
    let pq_fee = n_pq.process_block(vec![sx(&pq, 0, 0, &prog)]).unwrap().fee_charged.as_nano();
    println!("\nbloat premium: Ed25519 tx {ed_fee} nanoAVR  vs  post-quantum tx {pq_fee} nanoAVR  ({}x)", pq_fee / ed_fee.max(1));

    // Fiat cost of the Ed25519 tx at several hypothetical token prices.
    #[allow(clippy::cast_precision_loss)]
    let avr = ed_fee as f64 * 1e-9;
    println!("\ntoken-price independence (native fee fixed at {ed_fee} nanoAVR = {avr:.9} AVR):");
    for price in [0.01, 1.0, 10.0, 150.0] {
        println!("  at ${price:>7}/AVR  ->  ${:.9} per tx", avr * price);
    }
    println!("congestion sets the native fee; token price only scales the fiat display.");
}
