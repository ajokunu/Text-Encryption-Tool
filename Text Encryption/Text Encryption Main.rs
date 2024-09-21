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

fn generate_nonce() -> [u8; 12] {
    let mut rng = OsRng;
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce);
    nonce
}

fn encrypt(plaintext: &str, shared_secret: &[u8]) -> String {
    let key = Key::from_slice(shared_secret);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice( &nonce_bytes); 
    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes()).unwrap();
    (encode(ciphertext), nonce_bytes)
}

fn decrypt(ciphertext: &str, shared_secret: &[u8], nonce_bytes: &[u8; 12]) -> String {
    let key = Key::from_slice(shared_secret);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let ciphertext = decode(ciphertext).unwrap();
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
    String::from_utf8(plaintext).unwrap()
}

fn main() {
    let plaintext = "This is an encrypted message, decrypt to decipher";

    // Generate keypair
    let (public_key, secret_key) = generate_keypair();

    // Encapsulate to get ciphertext and shared secret
    let (ciphertext, key2_shared_secret) = encapsulation(&public_key);

    // Decapsulate to get the same shared secret
    let bob_shared_secret = decapsulation(&ciphertext, &secret_key);

    assert_eq!(key2_shared_secret, bob_shared_secret, "These Shared secrets don't match!");

    // Encrypt and decrypt the message
    let (encrypted, nonce) = encrypt(plaintext, &key2_shared_secret);
    println!("Encrypted (base64): {}", encrypted);

    let decrypted = decrypt(&encrypted, &bob_shared_secret, &nonce);
    println!("Decrypted: {}", decrypted);

    assert_eq!(plaintext, decrypted, "Decryption failed!")
}