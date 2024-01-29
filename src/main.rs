use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{generator, prepare_verifying_key, verifier, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use ark_std::test_rng;
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;

fn main() {
    // Message to be signed
    let message = "Hello, world!";

    // Private key of HMAC
    let private_key = "my_secret_key";

    // Public signature of HMAC
    let public_signature = "my_public_signature";

    // Generate random parameters for Groth16 proof system
    let rng = &mut test_rng();
    let params = generate_random_parameters::<Sha256, _, _>(10, rng).unwrap();

    // Prepare verifying key for Groth16 proof system
    let vk = prepare_verifying_key(&params.vk);

    // Verify the proof
    let proof = Proof::deserialize_with_mode(&hex::decode(public_signature).unwrap()[..]).unwrap();
    let mut cs = params.new_circuit();
    cs.alloc_input(|| Ok(Sha256::Digest(message.as_bytes()).to_vec())).unwrap();
    cs.alloc_input(|| Ok(hex::decode(private_key).unwrap())).unwrap();
    cs.alloc_input(|| Ok(hex::decode(public_signature).unwrap())).unwrap();
    let result = verifier(&vk, &proof, &cs).unwrap();
    assert!(result);
}
