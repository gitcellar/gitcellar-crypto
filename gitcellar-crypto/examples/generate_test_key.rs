//! Generate a test key and print it

use gitcellar_crypto::Identity;

fn main() {
    let identity = Identity::generate("test-user").expect("Failed to generate identity");
    let public_key = identity.export_public_key().expect("Failed to export public key");
    let fingerprint = identity.fingerprint();

    println!("=== PUBLIC KEY ===");
    println!("{}", public_key);
    println!("=== FINGERPRINT ===");
    println!("{}", fingerprint);
}
