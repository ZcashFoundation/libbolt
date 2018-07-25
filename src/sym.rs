/*
    Symmetric Key Encryption Scheme.
*/
use std::fmt;
use sodiumoxide;
use sodiumoxide::init;
use sodiumoxide::crypto::secretbox;

pub struct SymCT {
    nonce: secretbox::Nonce,
    ciphertext: Vec<u8>
}


impl fmt::Display for SymCT {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut y_s = String::new();
        for y in self.ciphertext.iter() {
            y_s = format!("{}{:x}", y_s, y);
        }

        write!(f, "CT : (ct=0x{})", y_s)
    }
}

#[derive(Clone)]
pub struct SymKey {
    key: secretbox::Key,
    l: i32
}

pub fn init_mod() {
    sodiumoxide::init();
}

pub fn keygen(l: i32) -> SymKey {
    // TODO: make sure key is a l-bit key
    return SymKey { key: secretbox::gen_key(), l: l };
}

pub fn encrypt(key: &SymKey, plaintext: &String) -> SymCT {
    let nonce = secretbox::gen_nonce();
    let pt = plaintext.as_bytes();
    let ct = secretbox::seal(pt, &nonce, &key.key);
    return SymCT { nonce: nonce, ciphertext: ct };
}

pub fn decrypt(key: &SymKey, ciphertext: &SymCT) -> String {
    let nonce = ciphertext.nonce;
    let pt = secretbox::open(&ciphertext.ciphertext, &nonce, &key.key).unwrap();
    // TODO: investigate better error handling here
    let plaintext = String::from_utf8(pt).expect("Found invalid UTF-8");
    return plaintext;
}


#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, thread_rng};

    #[test]
    fn symenc_dec_works() {
        init_mod();
        // SymKeyEnc tests
        // TODO: figure out how to apply this to secretbox
        let l = 128;
        let key1 = keygen(l);

        // println!("key: {:?}", key);

        let pt1 = String::from("hello world");
        let ciphertext = encrypt(&key1, &pt1);
        //println!("{}", ciphertext);

        let pt2 = decrypt(&key1, &ciphertext);
        //println!("Recovered plaintext: {}", pt2);
        assert!(pt1 == pt2);
    }

    #[test]
    #[should_panic]
    fn symenc_dec_should_fail() {
        init_mod();
        // SymKeyEnc tests
        // TODO: figure out how to apply this to secretbox
        let l = 128;

        let key1 = keygen(l);
        let key2 = keygen(l);

        let pt1 = String::from("hello world");
        let ciphertext = encrypt(&key1, &pt1);

        let pt3 = decrypt(&key2, &ciphertext);
        // should fail and panic
    }
}