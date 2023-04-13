use std::collections::{BTreeMap, HashMap};

use post::{
    difficulty::proving_difficulty,
    prove::{ConstDProver, Prover, ProvingParams},
    ScryptParams,
};
use rand::{thread_rng, RngCore};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};

struct ParamSet {
    pub k1: u32,
    pub k2: u32,
}

fn try_set(data: &[u8], set: ParamSet, num_labels: usize, target_proofs: usize) {
    println!(
        "Trying set: k1={}, k2={}, held data: {}%",
        set.k1,
        set.k2,
        data.len() / 16 * 100 / num_labels,
    );

    let params = ProvingParams {
        pow_scrypt: ScryptParams::new(1, 0, 0),
        difficulty: proving_difficulty(num_labels as u64, set.k1).unwrap(),
        k2_pow_difficulty: u64::MAX,
        k3_pow_difficulty: u64::MAX,
    };

    let find_proof = |ch| -> u32 {
        let mut indicies = HashMap::<u32, Vec<u64>>::new();
        for nonce in (0..).step_by(2) {
            indicies.clear();

            let prover = ConstDProver::new(&ch, nonce..nonce + 2, params.clone());

            let result = prover.prove(data, 0, |nonce, index| {
                let vec = indicies.entry(nonce).or_default();
                vec.push(index);
                if vec.len() >= set.k2 as usize {
                    return Some(std::mem::take(vec));
                }
                None
            });

            if let Some((nonce, _)) = result {
                print!("*");
                return nonce;
            }
        }
        unreachable!()
    };

    let nonces = (0u64..target_proofs as u64)
        .into_par_iter()
        .map(|i| {
            let challenge = i.to_le_bytes().repeat(4).as_slice().try_into().unwrap();
            find_proof(challenge)
        })
        .fold(BTreeMap::<u32, usize>::new, |mut counts, nonce| {
            *counts.entry(nonce).or_default() += 1;
            counts
        })
        .reduce(BTreeMap::<u32, usize>::new, |mut total_counts, counts| {
            for (nonce, count) in counts {
                *total_counts.entry(nonce).or_default() += count;
            }
            total_counts
        });

    let mut wtr = csv::WriterBuilder::new()
        .delimiter(b';')
        .from_path(format!(
            "./nonces-k1={}-k2={}-{}%.csv",
            set.k1,
            set.k2,
            data.len() / 16 * 100 / num_labels
        ))
        .unwrap();
    wtr.write_record(["nonce", "proofs count"]).unwrap();

    for (nonce, count) in nonces.iter() {
        wtr.write_record(&[nonce.to_string(), count.to_string()])
            .unwrap();
    }

    wtr.flush().unwrap();
}

// fn probability_to_find_proof_with_n_nonces(data: &[u8], set: ParamSet, num_labels: usize, nonces: usize) {
//     println!(
//         "Trying set: k1={}, k2={}, held data: {}%",
//         set.k1,
//         set.k2,
//         data.len() / 16 * 100 / num_labels,
//     );

//     let params = ProvingParams {
//         pow_scrypt: ScryptParams::new(1, 0, 0),
//         difficulty: proving_difficulty(num_labels as u64, set.k1).unwrap(),
//         k2_pow_difficulty: u64::MAX,
//         k3_pow_difficulty: u64::MAX,
//     };

//     let find_proof = |ch| -> u32 {
//         let mut indicies = HashMap::<u32, Vec<u64>>::new();
//         for nonce in (0..).step_by(2) {
//             indicies.clear();

//             let prover = ConstDProver::new(&ch, nonce..nonce + 2, params.clone());

//             let result = prover.prove(data, 0, |nonce, index| {
//                 let vec = indicies.entry(nonce).or_default();
//                 vec.push(index);
//                 if vec.len() >= set.k2 as usize {
//                     return Some(std::mem::take(vec));
//                 }
//                 None
//             });

//             if let Some((nonce, _)) = result {
//                 print!("*");
//                 return nonce;
//             }
//         }
//         unreachable!()
//     };

//     let nonces = Mutex::new(BTreeMap::<u32, usize>::new());
//     (0u64..target_proofs as u64).into_par_iter().for_each(|i| {
//         let challenge = i.to_le_bytes().repeat(4).as_slice().try_into().unwrap();
//         let nonce = find_proof(challenge);
//         *nonces.lock().unwrap().entry(nonce).or_default() += 1;
//     });

//     let mut wtr = csv::WriterBuilder::new()
//         .delimiter(b';')
//         .from_path(format!(
//             "./nonces-k1={}-k2={}-{}%.csv",
//             set.k1,
//             set.k2,
//             data.len() / 16 * 100 / num_labels
//         ))
//         .unwrap();
//     wtr.write_record(["nonce", "proofs count"]).unwrap();

//     for (nonce, count) in nonces.lock().unwrap().iter() {
//         wtr.write_record(&[nonce.to_string(), count.to_string()])
//             .unwrap();
//     }

//     wtr.flush().unwrap();
// }

#[test]
fn probabilities_to_find_prove_given_nonces() {
    let num_labels = 1e6 as usize;
    let mut data = vec![0u8; num_labels * 16];
    thread_rng().fill_bytes(&mut data);

    for test in [
        (
            ParamSet { k1: 196, k2: 200 },
            &data[..data.len() * 100 / 100],
            10000,
        ),
        // (
        //     ParamSet { k1: 279, k2: 300 },
        //     &data[..data.len() * 100 / 100],
        //     10000,
        // ),
        // (
        //     ParamSet { k1: 300, k2: 300 },
        //     &data[..data.len() * 100 / 100],
        //     10000,
        // ),
        // (
        //     ParamSet { k1: 118, k2: 120 },
        //     &data[..data.len() * 100 / 100],
        //     10000,
        // ),
        // (
        //     ParamSet { k1: 196, k2: 200 },
        //     &data[..data.len() * 80 / 100],
        //     1000,
        // ),
        // (
        //     ParamSet { k1: 300, k2: 300 },
        //     &data[..data.len() * 80 / 100],
        //     1000,
        // ),
        // (
        //     ParamSet { k1: 118, k2: 120 },
        //     &data[..data.len() * 70 / 100],
        //     200,
        // ),
        // (
        //     ParamSet { k1: 279, k2: 300 },
        //     &data[..data.len() * 85 / 100],
        //     100,
        // ),
    ] {
        try_set(test.1, test.0, num_labels, test.2);
    }
}
