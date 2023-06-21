use post::{
    initialize::{CpuInitializer, Initialize},
    metadata::ProofMetadata,
    prove::generate_proof,
    verification::{Verifier, VerifyingParams},
    ScryptParams,
};
use randomx_rs::RandomXFlag;
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use tempfile::tempdir;

fn main() {
    println!("Hello, world!");

    let challenge = b"hello world, challenge me!!!!!!!";
    let labels_per_unit = 200;
    let datadir = tempdir().unwrap();

    let cfg = post::config::Config {
        k1: 20,
        k2: 30,
        k3: 30,
        k2_pow_difficulty: u64::MAX,
        pow_scrypt: ScryptParams::new(2, 0, 0),
        pow_difficulty: [0x0F; 32],
        scrypt: ScryptParams::new(1, 0, 0),
    };

    let metadata = CpuInitializer::new(cfg.scrypt)
        .initialize(
            datadir.path(),
            &[0u8; 32],
            &[0u8; 32],
            labels_per_unit,
            2,
            labels_per_unit,
            None,
        )
        .unwrap();

    let pow_flags = RandomXFlag::get_recommended_flags();
    // Generate a proof
    let proof = generate_proof(datadir.path(), challenge, cfg, 32, 1, pow_flags).unwrap();

    // Verify the proof
    let metadata = ProofMetadata {
        node_id: metadata.node_id,
        commitment_atx_id: metadata.commitment_atx_id,
        challenge: *challenge,
        num_units: metadata.num_units,
        labels_per_unit: metadata.labels_per_unit,
    };
    let verifier = Verifier::new(pow_flags).unwrap();
    (0..10000).into_par_iter().for_each(|pow| {
        let mut proof = proof.clone();
        proof.pow = pow;

        let res = verifier.verify(
            &proof,
            &metadata,
            VerifyingParams::new(&metadata, &cfg).unwrap(),
        );

        println!("pow: {pow}, res: {res:?}");
    });
}
