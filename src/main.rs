use bellman::{groth16, Circuit};
use bls12_381::Bls12;
use ff::PrimeField;
use pairing::Engine;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};
use bellman::gadgets::boolean::Boolean;
use bellman::gadgets::boolean::AllocatedBit;
struct MyCircuit {
    message: Option<Vec<u8>>,
    code: Option<Vec<u8>>,
    key: Option<Vec<u8>>,
}

impl<Bls12: PrimeField> Circuit<Bls12> for MyCircuit {
    fn synthesize<CS: bellman::ConstraintSystem<Bls12>>(
        self,
        cs: &mut CS,
    ) -> Result<(), bellman::SynthesisError> {
        let message = self.message.map(|v| {
            v.into_iter()
                .map(|byte| {
                    let mut bits = Vec::new();
                    for i in 0..8 {
                        bits.push(Boolean::Is(
                            AllocatedBit::alloc(cs.namespace(|| format!("message bit {}", i)), Some((byte >> i) & 1u8 == 1u8))
                                .unwrap()
                        ));
                    }
                    bits
                })
                .flatten()
                .collect::<Vec<_>>()
        }).unwrap_or_else(|| vec![]);

        let code = self.code.map(|v| {
            v.into_iter()
                .map(|byte| {
                    let mut bits = Vec::new();
                    for i in 0..8 {
                        bits.push(Boolean::Is(
                            AllocatedBit::alloc(cs.namespace(|| format!("code bit {}", i)), Some((byte >> i) & 1u8 == 1u8))
                                .unwrap()
                        ));
                    }
                    bits
                })
                .flatten()
                .collect::<Vec<_>>()
        }).unwrap_or_else(|| vec![]);

        let key = self.key.map(|v| {
            v.into_iter()
                .map(|byte| {
                    let mut bits = Vec::new();
                    for i in 0..8 {
                        bits.push(Boolean::Is(
                            AllocatedBit::alloc(cs.namespace(|| format!("key bit {}", i)), Some((byte >> i) & 1u8 == 1u8))
                                .unwrap()
                        ));
                    }
                    bits
                })
                .flatten()
                .collect::<Vec<_>>()
        }).unwrap_or_else(|| vec![]);

        let mut mac = Hmac::<Sha256>::new_varkey(&key).unwrap();
        mac.input(&message);
        let result = mac.result().code().to_vec();

        let code_bits = code
            .into_iter()
            .map(|bit| bit.get_value().unwrap())
            .collect::<Vec<_>>();

        let result_bits = result
            .into_iter()
            .map(|byte| {
                (0..8)
                    .map(|i| ((byte >> i) & 1u8) == 1u8)
                    .collect::<Vec<_>>()
            })
            .flatten()
            .collect::<Vec<_>>();

        let mut input_bits = Vec::new();
        input_bits.extend(code_bits);
        input_bits.extend(result_bits);

        let input_vars = input_bits
            .into_iter()
            .enumerate()
            .map(|(i, bit)| {
                Boolean::Is(AllocatedBit::alloc(
                    cs.namespace(|| format!("input bit {}", i)),
                    Some(bit),
                ).unwrap())
            })
            .collect::<Vec<_>>();

        let params = groth16::generate_random_parameters::<Bls12, _, _>(
            MyCircuit {
                message: None,
                code: None,
                key: None,
            },
            &mut OsRng,
        )
        .unwrap();

        let verifying_key = groth16::prepare_verifying_key(&params.vk);
        let proof = groth16::create_random_proof(MyCircuit { message: None, code: None, key: None }, &params, &mut OsRng).unwrap();
        assert!(groth16::verify_proof(&verifying_key, &proof, &input_vars[..]).unwrap());

        Ok(())
    }
}

fn main() {
    let message = b"Hello, world!";
    let key = b"my secret and secure key";

    let code = Hmac::<Sha256>::new_varkey(&key).unwrap().result().code().to_vec();

    let circuit = MyCircuit {
        message: Some(message.to_vec()),
        code: Some(code.to_vec()),
        key: Some(key.to_vec()),
    };

    // Generate random parameters for the zk-SNARK circuit
    let params = groth16::generate_random_parameters::<Bls12, _, _>(circuit.clone(), &mut OsRng).unwrap();

    // Prepare the verifying key
    let pvk = groth16::prepare_verifying_key(&params.vk);

    // Create a proof for the given circuit and parameters
    let proof = groth16::create_random_proof(circuit.clone(), &params, &mut OsRng).unwrap();

    // Verify the proof using the verifying key and input variables
    let is_proof_valid = groth16::verify_proof(&pvk, &proof, &[]).unwrap();

    // Output the result of the proof verification
    if is_proof_valid {
        println!("Proof is valid!");
    } else {
        println!("Proof is invalid!");
    }
}