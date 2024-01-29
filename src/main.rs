use ark_std::rand::thread_rng;
use ark_std::vec::Vec;
use ark_groth16::{Parameters, Proof, verify_proof, create_random_proof, Prover};
use ark_crypto_primitives::{snark::ProvingKey, SNARK, Error};
use ark_relations::r1cs::{ConstraintSystem, SynthesisError};

use sha2::Sha256;
use hex::encode;
use ark_crypto_primitives::fixed_length_crh::FixedLengthCRH;
use ark_ff::{PrimeField, Fq};
use ark_bls12_381::Bls12;

type Bls12 = ark_bls12_381::Bls12;
type Fq = <Bls12 as PrimeField>::Fq;

const MESSAGE: &[u8] = b"This is the message to be signed";

fn generate_keys() -> Result<(ProvingKey<Bls12>, ark_groth16::VerifyingKey<Bls12>), Error> {
    let rng = &mut thread_rng();
    let circuit = HmacCircuit::new(MESSAGE);
    let pk = ProvingKey::<Bls12>::generate(rng, circuit)?;
    Ok((pk, pk.vk.clone()))
}

fn create_proof(
    pk: &ProvingKey<Bls12>,
    message: &[u8],
) -> Result<Proof<Bls12>, ark_groth16::Error> {
    let circuit = HmacCircuit::new(message);
    create_random_proof(pk, circuit, &mut thread_rng())
}

const SHA256_BLOCK_SIZE: usize = 32; // SHA-256 block size in bytes
const SECRET_SHARE_COUNT: usize = 4; // Number of key shares

struct HmacCircuit<'a> {
    message: &'a [u8],
    // Secret-shared key shares represented as field elements
    key_shares: [Fq; SECRET_SHARE_COUNT],
}

impl<'a> ConstraintSynthesizer<Bls12> for HmacCircuit<'a> {
    fn generate_constraints<CS: ConstraintSystem<Bls12>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let message_bits = alloc_bits(cs, self.message)?;
        let mut hmac_state = [Fq::zero(); SHA256_BLOCK_SIZE]; // Allocate field elements for HMAC state

        // Pad message to an exact multiple of 32 bytes
        let padded_message = pad_message(self.message);

        // Iterate through message blocks and update HMAC state
        for block in padded_message.chunks(SHA256_BLOCK_SIZE) {
            let block_bits = alloc_bits(cs, block)?;
            let block_field = field_from_bits(cs, block_bits)?;
            update_hmac_state(cs, &mut hmac_state, block_field, &self.key_shares)?;
        }

        // Convert final HMAC state to digest
        let digest_field = field_from_bits(cs, hmac_state)?;

        // Enforce key share consistency constraints
        let sum_constraint = self.key_shares.iter().fold(Fq::zero(), |acc, &share| acc + share);
        cs.enforce_constraint(sum_constraint == Fq::zero(), "Key shares sum to the original key");

        // Enforce signature verification constraint
        let signature_bytes = hmac_state_to_bytes(hmac_state);
        let signature_field = field_from_bytes(cs, &signature_bytes)?;
        cs.enforce_constraint(
            digest_field == signature_field,
            "HMAC digest matches signature",
        );

        Ok(())
    }
}

fn main() -> Result<(), ark_groth16::Error> {
    // Generate Groth16 proving and verifying keys (one-time operation)
    let (pk, vk) = generate_keys()?;

    // Dummy key shares for demonstration purposes
    let key_shares = [Fq::rand(), Fq::rand(), Fq::rand(), Fq::rand()];

    // Create a proof for the given message
    let proof = create_proof(&pk, MESSAGE)?;

    // Verify the proof
    let verified = verify_proof(&vk, &proof, MESSAGE)?;
    assert!(verified);

    println!("Proof verification successful!");

    Ok(())
}

// Helper functions
fn pad_message(message: &[u8]) -> Vec<u8> {
    let block_size = SHA256_BLOCK_SIZE;
    let padding_length = block_size - (message.len() % block_size);

    let mut padded_message = message.to_vec();

    // Append padding bytes
    for _ in 0..padding_length {
        padded_message.push(padding_length as u8);
    }

    padded_message
}

fn alloc_bits<CS: ConstraintSystem<Bls12>>(cs: &mut CS, data: &[u8]) -> Result<Vec<ark_relations::r1cs::Variable>, SynthesisError> {
    let mut bits = Vec::new();

    for byte in data {
        let byte_bits = byte.to_bits_le();
        for bit in byte_bits.iter() {
            bits.push(cs.alloc(
                || "allocation of bit",
                || {
                    Ok(if *bit { Fq::one() } else { Fq::zero() })
                },
            )?);
        }
    }

    Ok(bits)

}

fn field_from_bits<CS: ConstraintSystem<Bls12>>(
    cs: &mut CS,
    bits: Vec<ark_relations::r1cs::Variable>,
) -> Result<Fq, SynthesisError> {
    let mut result = Fq::zero();
    let mut power_of_two = Fq::one();

    for bit in bits {
        result += &power_of_two * bit.get_value().unwrap();
        power_of_two.double_in_place();
    }

    // Allocate the final field element
    let result_var = cs.alloc(
        || "allocation of field element",
        || {
            Ok(result)
        },
    )?;

    // Enforce equality with the reconstructed field element
    cs.enforce_constraint(
        result_var.get_variable().get_variable() == cs.linear_combination(&bits),
        "field element reconstruction constraint",
    );

    Ok(result)
}

fn update_hmac_state<CS: ConstraintSystem<Bls12>>(
    cs: &mut CS,
    hmac_state: &mut [Fq; SHA256_BLOCK_SIZE],
    block_field: Fq,
    key_shares: &[Fq],
) -> Result<(), SynthesisError> {
    // Convert block_field to bytes
    let block_bytes = block_field.to_bytes();

    // XOR the block with the key shares
    let mut xor_result = [0u8; SHA256_BLOCK_SIZE];
    for (byte, &key_share) in block_bytes.iter().zip(key_shares.iter()) {
        xor_result.iter_mut().zip(byte.iter()).for_each(|(result_byte, key_byte)| {
            *result_byte ^= key_byte;
        });

        // Multiply each byte by the corresponding key share
        xor_result.iter_mut().for_each(|result_byte| {
            *result_byte = Fq::from(*result_byte) * key_share;
        });
    }

    // Convert xor_result back to field elements
    let xor_result_field = field_from_bytes(cs, &xor_result)?;

    // Update the HMAC state using the SHA-256 compression function
    update_sha256_hmac_state(hmac_state, xor_result_field);

    Ok(())
}
fn update_sha256_hmac_state(hmac_state: &mut [Fq; SHA256_BLOCK_SIZE], data: Fq) {
    // Convert Fq to bytes
    let data_bytes = data.to_bytes();

    // Use the SHA-256 compression function to update the HMAC state
    let mut hasher = Sha256::new();
    hasher.input(data_bytes);
    let digest = hasher.result();

    for (state_byte, digest_byte) in hmac_state.iter_mut().zip(digest.iter()) {
        *state_byte = Fq::from(*state_byte) + Fq::from(*digest_byte);
    }
}

fn field_from_bytes<CS: ConstraintSystem<Bls12>>(
    cs: &mut CS,
    bytes: &[u8],
) -> Result<Fq, SynthesisError> {
    // Read a little-endian u64 from the bytes
    let mut reader = Cursor::new(bytes);
    let mut buf = [0u8; 64]; // Assuming the field element is represented by 64 bytes
    reader.read_exact(&mut buf)?;

    let value = from_le_bytes(&buf);
    
    // Allocate the field element variable
    let var = cs.alloc(
        || "allocation of field element",
        || {
            Ok(value.ok_or_else(|| SynthesisError::AssignmentMissing)?)
        },
    )?;

    // Enforce equality with the reconstructed field element
    cs.enforce_constraint(
        var.get_variable().get_variable() == cs.linear_combination(&[var.clone()]),
        "field element reconstruction constraint",
    );

    Ok(value.ok_or_else(|| SynthesisError::AssignmentMissing)?)
}

fn hmac_state_to_bytes(hmac_state: [Fq; SHA256_BLOCK_SIZE]) -> Vec<u8> {
    let mut result = Vec::new();

    for element in hmac_state.iter() {
        // Convert each field element to bytes
        let element_bytes = element.to_bytes();

        // Append the bytes to the result vector
        result.extend_from_slice(&element_bytes);
    }

    result
}