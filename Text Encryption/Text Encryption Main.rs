use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret};
use rand::rngs::OsRng;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use base64::{encode, decode};

fn generate_encryption_kp(Vec<u8>) -> (Vec<u8>) {
    let (public_key, secret_key) = kyber768::keypair();
    (public_key.as_bytes().to_vec(), secret_key.as_bytes().to_vec())
}

fn encapsulation(public_key: &[u8]) -> ( Vec<u8>, Vec<u8>) {
    let public_key = kyber768::PublicKey::from_bytes(public_key).unwrap();
    let(Ciphertext, shared secret) = kyber768::encapsulate(&public_key);
    (Ciphertextiphertext.as_bytes().to_vec(), shared_secret.as_bytes().to_vec())
}

fn decapsulation(Ciphertext: &[u8], secret: &[u8]) -> Vec<u8>) {
    let Ciphertext = kyber768::Ciphertext::from_bytes(Ciphertext).unwrap();
    let secret_key = kyber768::SecretKey::from_bytes(Ciphertext).unwrap();
    let shared_secret = kyber768::decapsulate(&Ciphertext, &secret_key);
    shared_secret.as_bytes().to_vec()
}