extern crate bn;
extern crate rand;
extern crate bincode;
extern crate sodiumoxide;
extern crate rustc_serialize;
extern crate secp256k1;

use std::fmt;
use std::str;
use std::default;
use std::result;
use bn::{Group, Fr, G1, G2, Gt, pairing};
use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::{encode, decode};
use sodiumoxide::randombytes;
use sodiumoxide::crypto::hash::sha512;
use std::collections::HashMap;

pub mod prf;
pub mod sym;
pub mod ote;
pub mod clsigs;
pub mod commit_scheme;

// Begin CL Signature scheme data structures

// End CL Signature scheme data structures

//pub fn hash_string(s: &str) -> String {
//    let digest = sha256::hash(s.as_bytes());
//    format!("{:X}", HexSlice::new(&digest))
//}

pub fn debug_elem_in_hex(prefix: &str, r: &Fr) {
    let encoded: Vec<u8> = encode(&r, Infinite).unwrap();
    print!("{} (hex) = 0x", prefix);
    for e in encoded.iter() {
        print!("{:x}", e);
    }
    print!("\n");
}

pub fn debug_g1_in_hex(prefix: &str, g: &G1) {
    let encoded: Vec<u8> = encode(&g, Infinite).unwrap();
    print!("{} (hex) = 0x", prefix);
    for e in encoded.iter() {
        print!("{:x}", e);
    }
    print!("\n");
}

pub fn debug_g2_in_hex(prefix: &str, g: &G2) {
    let encoded: Vec<u8> = encode(&g, Infinite).unwrap();
    print!("{} (hex) = 0x", prefix);
    for e in encoded.iter() {
        print!("{:x}", e);
    }
    print!("\n");
}

pub fn debug_gt_in_hex(prefix: &str, g: &Gt) {
    let encoded: Vec<u8> = encode(&g, Infinite).unwrap();
    print!("{} (hex) = 0x", prefix);
    for e in encoded.iter() {
        print!("{:x}", e);
    }
    print!("\n");
}


struct HexSlice<'a>(&'a [u8]);

impl<'a> HexSlice<'a> {
    fn new<T>(data: &'a T) -> HexSlice<'a>
        where T: ?Sized + AsRef<[u8]> + 'a
    {
        HexSlice(data.as_ref())
    }
}

impl<'a> fmt::LowerHex for HexSlice<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.0 {
            // Decide if you want upper- or lowercase results,
            // padding the values to two characters, spaces
            // between bytes, etc.
            write!(f, "{:x}", byte)?;
        }
        Ok(())
    }
}

impl<'a> fmt::UpperHex for HexSlice<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.0 {
            // Decide if you want upper- or lowercase results,
            // padding the values to two characters, spaces
            // between bytes, etc.
            write!(f, "{:X}", byte)?;
        }
        Ok(())
    }
}
// To hash this message structure, encode each element in the tuple
// as a byte stream, then apply a hash on it. Then, convert the output value into
// a Fr element.

pub fn misc_tests() {
    let rng = &mut rand::thread_rng();
    let a = Fr::random(rng);
    // println!("crs = {}", stringify!(a));
    // let limit = bincode::SizeLimit::Bounded(256);
    let encoded: Vec<u8> = encode(&a, Infinite).unwrap();
    println!("a length = {}", encoded.len());
    println!("a = {:?}", encoded);
    print!("a (hex) = 0x");
    for x in encoded.iter() {
        print!("{:x}", x);
    }
    print!("\n");

}

pub fn print(g: &G1) -> String {
    let c_vec: Vec<u8> = encode(g, Infinite).unwrap();
    let mut c_s = String::new();
    for x in c_vec.iter() {
        c_s = format!("{}{:x}", c_s, x);
    }

    return c_s;
}

////////////////////////////////// ZK proof compiler ///////////////////////////////////

//pub mod zkp {
//
//#[macro_export]
//macro_rules! log {
//    ($msg:expr) => {{
//        let state: i32 = get_log_state();
//        if state > 0 {
//            println!("log({}): {}", state, $msg);
//        }
//    }};
//}
//
//#[doc(hidden)]
//#[macro_export]
//macro_rules! __compute_formula_scalarlist {
//    // Unbracket a statement
//    (($publics:ident, $scalars:ident) ($($x:tt)*)) => {
//        // Add a trailing +
//        __compute_formula_scalarlist!(($publics,$scalars) $($x)* +)
//    };
//    // Inner part of the formula: give a list of &Scalars
//    // Since there's a trailing +, we can just generate the list as normal...
//    (($publics:ident, $scalars:ident)
//     $( $point:ident * $scalar:ident +)+ ) => {
//        &[ $( $scalars.$scalar ,)* ]
//    };
//}
//
//#[doc(hidden)]
//#[macro_export]
//macro_rules! __compute_formula_pointlist {
//    // Unbracket a statement
//    (($publics:ident, $scalars:ident) ($($x:tt)*)) => {
//        // Add a trailing +
//        __compute_formula_pointlist!(($publics,$scalars) $($x)* +)
//    };
//    // Inner part of the formula: give a list of &Scalars
//    // Since there's a trailing +, we can just generate the list as normal...
//    (($publics:ident, $scalars:ident)
//     $( $point:ident * $scalar:ident +)* ) => {
//        &[ $( *($publics.$point) ,)* ]
//    };
//}
//
//#[doc(hidden)]
//#[macro_export]
//macro_rules! __compute_commitments_consttime {
//    (($publics:ident, $scalars:ident) $($lhs:ident = $statement:tt),+) => {
//        Commitments {
//            $( $lhs :
//               multiscalar_mult(
//                   __compute_formula_scalarlist!(($publics, $scalars) $statement),
//                   __compute_formula_pointlist!(($publics, $scalars) $statement),
//               )
//            ),+
//        }
//    }
//}
//
//#[doc(hidden)]
//#[macro_export]
//macro_rules! __recompute_commitments_vartime {
//    (($publics:ident, $scalars:ident, $minus_c:ident) $($lhs:ident = $statement:tt),+) => {
//        Commitments {
//            $( $lhs :
//               vartime::multiscalar_mult(
//                   __compute_formula_scalarlist!(($publics, $scalars) $statement)
//                       .into_iter()
//                       .chain(iter::once(&($minus_c)))
//                   ,
//                   __compute_formula_pointlist!(($publics, $scalars) $statement)
//                       .into_iter()
//                       .chain(iter::once($publics.$lhs))
//               )
//            ),+
//        }
//    }
//}
//
//#[macro_export]
//macro_rules! create_nipk {
//(
//    $proof_module_name:ident // Name of the module to create
//    ,
//    ( $($secret:ident),+ ) // Secret variables, sep by commas
//    ,
//    ( $($public:ident),+ ) // Public variables, sep by commas
//    :
//    // List of statements to prove
//    // Format: LHS = ( ... RHS expr ... ),
//    $($lhs:ident = $statement:tt),+
//) => {
//    mod $proof_module_name {
//        use $crate::{Group, Fr, G1}
//        use $crate::sodiumoxide::crypto::hash;
//        // use $crate::sha2::{Digest, Sha512};
//        use $crate::rand::Rng;
//
//        use std::iter;
//
//        #[derive(Copy, Clone)]
//        pub struct Secrets<'a> {
//            // Create a parameter for each secret value
//            $(
//                pub $secret : &'a Fr,
//            )+
//        }
//
//        #[derive(Copy, Clone)]
//        pub struct Publics<'a> {
//            // Create a parameter for each public value
//            $(
//                pub $public : &'a G1,
//            )+
//        }
//
//        // Hack because we can't concat identifiers,
//        // so do responses.x instead of responses_x
//        // rand.x instead of rand_x, etc.
//
//        struct Commitments {$($lhs: G1,)+ }
//        struct Randomnesses {$($secret : Scalar,)+}
//        #[derive(Serialize, Deserialize)]
//        struct Responses {$($secret : Scalar,)+}
//
//        #[derive(Serialize, Deserialize)]
//        pub struct Proof {
//            challenge: Fr,
//            responses: Responses,
//        }
//
//        impl Proof {
//            /// Create a `Proof`, in constant time, from the given
//            /// `Publics` and `Secrets`.
//            #[allow(dead_code)]
//            pub fn create<R: Rng>(
//                rng: &mut R,
//                publics: Publics,
//                secrets: Secrets,
//            ) -> Proof {
//                let rand = Randomnesses{
//                    $(
//                        $secret : Fr::random(rng),
//                    )+
//                };
//                // $statement_rhs = `X * x + Y * y + Z * z`
//                // should become
//                // `publics.X * rand.x + publics.Y * rand.y + publics.Z * rand.z`
//                let commitments: Commitments;
//                commitments = __compute_commitments_consttime!(
//                    (publics, rand) $($lhs = $statement),*
//                );
//
//                let mut hash_state = hash::State::new();
//
//                $(
//                    hash_state.update(publics.$public.as_bytes());
//                )+
//                $(
//                    hash_state.update(commitments.$lhs.as_bytes());
//                )+
//
//                let digest = hash_state.finalize();
//                let mut digest_buf: [u8; 64] = [0; 64];
//                digest_buf.copy_from_slice(&digest[0..64]);
//                let challenge = Fr::interpret(&digest_buf); // Scalar::from_hash(hash);
//
//                let responses = Responses{
//                    $(
//                        $secret : &(&challenge * secrets.$secret) + &rand.$secret,
//                    )+
//                };
//
//                Proof{ challenge: challenge, responses: responses }
//            }
//
//            /// Verify the `Proof` using the public parameters `Publics`.
//            #[allow(dead_code)]
//            pub fn verify(&self, publics: Publics) -> Result<(),()> {
//                // `A = X * x + Y * y`
//                // should become
//                // `publics.X * responses.x + publics.Y * responses.y - publics.A * self.challenge`
//                let responses = &self.responses;
//                let minus_c = -&self.challenge;
//                let commitments = __recompute_commitments_vartime!(
//                    (publics, responses, minus_c) $($lhs = $statement),*
//                );
//
//                let mut hash_state = hash::State::new();
//                // Add each public point into the hash
//                $(
//                    hash_state.update(publics.$public.as_bytes());
//                )+
//                // Add each (recomputed) commitment into the hash
//                $(
//                    hash_state.update(commitments.$lhs.as_bytes());
//                )*
//
//                let digest = hash_state.finalize();
//                let mut digest_buf: [u8; 64] = [0; 64];
//                digest_buf.copy_from_slice(&digest[0..64]);
//                // Recompute challenge
//                let challenge = Fr::interpret(&digest_buf); // Scalar::from_hash(hash);
//
//                if challenge == self.challenge { Ok(()) } else { Err(()) }
//            }
//        }
//
//        #[cfg(test)]
//        mod bench {
//            extern crate test;
//
//            use $crate::rand;
//
//            use super::*;
//
//            use self::test::Bencher;
//
//            #[bench]
//            #[allow(dead_code)]
//            fn create(b: &mut Bencher) {
//                let rng = &mut rand::thread_rng();
//                //let mut rng = OsRng::new().unwrap();
//
//                // Need somewhere to actually put the public points
//                struct DummyPublics { $( pub $public : G1, )+ }
//                let dummy_publics = DummyPublics {
//                    $( $public : G1::random(&mut rng) , )+
//                };
//
//                let publics = Publics {
//                    $( $public : &dummy_publics.$public , )+
//                };
//
//                struct DummySecrets { $( pub $secret : Fr, )+ }
//                let dummy_secrets = DummySecrets {
//                    $( $secret : Fr::random(&mut rng) , )+
//                };
//
//                let secrets = Secrets {
//                    $( $secret : &dummy_secrets.$secret , )+
//                };
//
//                b.iter(|| Proof::create(&mut rng, publics, secrets));
//            }
//
//            #[bench]
//            #[allow(dead_code)]
//            fn verify(b: &mut Bencher) {
//                let mut rng = OsRng::new().unwrap();
//
//                // Need somewhere to actually put the public points
//                struct DummyPublics { $( pub $public : G1, )+ }
//                let dummy_publics = DummyPublics {
//                    $( $public : G1::random(&mut rng) , )+
//                };
//
//                let publics = Publics {
//                    $( $public : &dummy_publics.$public , )+
//                };
//
//                struct DummySecrets { $( pub $secret : Fr, )+ }
//                let dummy_secrets = DummySecrets {
//                    $( $secret : Fr::random(&mut rng) , )+
//                };
//
//                let secrets = Secrets {
//                    $( $secret : &dummy_secrets.$secret , )+
//                };
//
//                let p = Proof::create(&mut rng, publics, secrets);
//
//                b.iter(|| p.verify(publics));
//            }
//        }
//    }
//}
//}
//
//}
////////////////////////////////// ZK proof compiler ///////////////////////////////////

////////////////////////////////// SymKeyEnc ///////////////////////////////////
/*
    Symmetric Key Encryption Scheme.
*/
//pub mod sym {
//    use std::fmt;
//    use sodiumoxide;
//    use sodiumoxide::crypto::secretbox;
//
//    pub struct SymCT {
//        nonce: secretbox::Nonce,
//        ciphertext: Vec<u8>
//    }
//
//
//    impl fmt::Display for SymCT {
//        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//            let mut y_s = String::new();
//            for y in self.ciphertext.iter() {
//                y_s = format!("{}{:x}", y_s, y);
//            }
//
//            write!(f, "CT : (ct=0x{})", y_s)
//        }
//    }
//
//    #[derive(Clone)]
//    pub struct SymKey {
//        key: secretbox::Key,
//        l: i32
//    }
//
//    pub fn init() {
//        sodiumoxide::init();
//    }
//
//    pub fn keygen(l: i32) -> SymKey {
//        // TODO: make sure key is a l-bit key
//        return SymKey { key: secretbox::gen_key(), l: l };
//    }
//
//    pub fn encrypt(key: &SymKey, plaintext: &String) -> SymCT {
//        let nonce = secretbox::gen_nonce();
//        let pt = plaintext.as_bytes();
//        let ct = secretbox::seal(pt, &nonce, &key.key);
//        return SymCT { nonce: nonce, ciphertext: ct };
//    }
//
//    pub fn decrypt(key: &SymKey, ciphertext: &SymCT) -> String {
//        let nonce = ciphertext.nonce;
//        let pt = secretbox::open(&ciphertext.ciphertext, &nonce, &key.key).unwrap();
//        // TODO: investigate better error handling here
//        let plaintext = String::from_utf8(pt).expect("Found invalid UTF-8");
//        return plaintext;
//    }
//}

////////////////////////////////// SymKeyEnc ///////////////////////////////////

// OLD RefundMessage
//impl<'a> RefundMessage<'a> {
//    pub fn new(_c_id: Fr, _index: i32) -> RefundMessage<'a> {
//        RefundMessage {
//            prefix: "refund", c_id: _c_id, index: _index,
//        }
//    }
//
//    pub fn hash(&self) -> Fr {
//        let mut input_buf = Vec::new();
//        input_buf.extend_from_slice(self.prefix.as_bytes());
//        let c_id_vec: Vec<u8> = encode(&self.c_id, Infinite).unwrap();
//        // encode cId in the vector
//        input_buf.extend(c_id_vec);
//        // encoee the balance as a hex string
//        let b = format!("{:x}", self.index);
//        input_buf.extend_from_slice(b.as_bytes());
//        // TODO: add the ck vector (l-bit key)
////        let mut in_str = String::new();
////        for y in input_buf.iter() {
////            in_str = format!("{}{:x}", in_str, y);
////        }
////        println!("input_buf: {}", in_str);
//
//        // hash the inputs via SHA256
//        let sha2_digest = sha512::hash(input_buf.as_slice());
//        // println!("hash: {:?}", sha2_digest);
//        // let h = format!("{:x}", HexSlice::new(&sha2_digest));
//        let mut hash_buf: [u8; 64] = [0; 64];
//        hash_buf.copy_from_slice(&sha2_digest[0..64]);
//        return Fr::interpret(&hash_buf);
//    }
//}

// spend message (for unidirectional scheme)
#[derive(Clone)]
pub struct SpendMessage<'a> {
    prefix: &'a str,
    j: i32,
    s: G1,
    u: G1,
    pi: Proof,
    ck: sym::SymKey
}

impl<'a> SpendMessage<'a> {
    pub fn new(_j: i32, _s: G1, _u: G1, _pi: Proof, _ck: sym::SymKey) -> SpendMessage<'a> {
        SpendMessage {
            prefix: "spend", j: _j, s: _s, u: _u, pi: _pi, ck: _ck,
        }
    }

    pub fn hash(&self) -> Fr {
        // hash into a Fr element
        let rng = &mut rand::thread_rng();
        return Fr::random(rng);
    }
}

// coin message


////////////////////////////////// CL Sigs /////////////////////////////////////

////////////////////////////////// COMMITMENT //////////////////////////////////

#[derive(Copy, Clone)]
pub struct Message {
    sk: clsigs::SecretKey, // the secret key for the signature scheme (Is it possible to make this a generic field?)
    k1: Fr, // seed 1 for PRF
    k2: Fr, // seed 2 for PRF
    balance: i32 // the balance for the user
}

impl Message {
    pub fn new(_sk: clsigs::SecretKey, _k1: Fr, _k2: Fr, _balance: i32) -> Message {
        Message {
            sk: _sk, k1: _k1, k2: _k2, balance: _balance,
        }
    }

    pub fn hash(&self) -> Fr {
        let mut input_buf = self.sk.encode();
        // TODO: add sk_sigs to encode it
        let k1_vec: Vec<u8> = encode(&self.k1, Infinite).unwrap();
        let k2_vec: Vec<u8> = encode(&self.k2, Infinite).unwrap();
        // encode k1 in the vector
        input_buf.extend(k1_vec);
        // encode k2 in the vector
        input_buf.extend(k2_vec);
        // encoee the balance as a hex string
        let b = format!("{:x}", self.balance);
//        println!("Balance: {}", b);
        input_buf.extend_from_slice(b.as_bytes());
//        let mut in_str = String::new();
//        for y in input_buf.iter() {
//            in_str = format!("{}{:x}", in_str, y);
//        }
//        println!("input_buf: {}", in_str);

        // hash the inputs via SHA256
        let sha2_digest = sha512::hash(input_buf.as_slice());
        // println!("hash: {:?}", sha2_digest);
        // let h = format!("{:x}", HexSlice::new(&sha2_digest));
        let mut hash_buf: [u8; 64] = [0; 64];
        hash_buf.copy_from_slice(&sha2_digest[0..64]);
        return Fr::interpret(&hash_buf);
    }
}

////////////////////////////////// COMMITMENT //////////////////////////////////

////////////////////////////////// NIZKP //////////////////////////////////

pub fn concat_to_vector(output: &mut Vec<u8>, t: &G2) {
    let t_vec: Vec<u8> = encode(t, Infinite).unwrap();
    output.extend(t_vec);
}

#[derive(Copy, Clone)]
pub struct Proof {
    T: G1,
    c: Fr,
    s1: Fr,
    s2: Fr
}

//pub fn hash(g: &G1, h: &G1, X: &G1, Y: &G1, T: &Gt) -> Fr {
//    let g_vec: Vec<u8> = encode(&g, Infinite).unwrap();
//
//    // TODO: fix this
//    return Fr::from_str("1234567890").unwrap();
//}

pub fn hashG1ToFr(x: &G1) -> Fr {
    // TODO: change to serde (instead of rustc_serialize)
    let x_vec: Vec<u8> = encode(&x, Infinite).unwrap();
    let sha2_digest = sha512::hash(x_vec.as_slice());

    let mut hash_buf: [u8; 64] = [0; 64];
    hash_buf.copy_from_slice(&sha2_digest[0..64]);
    return Fr::interpret(&hash_buf);
}

pub fn hashPubKeyToFr(wpk: &secp256k1::PublicKey) -> Fr {
    let x_slice = wpk.serialize_uncompressed();
    let sha2_digest = sha512::hash(&x_slice);

    let mut hash_buf: [u8; 64] = [0; 64];
    hash_buf.copy_from_slice(&sha2_digest[0..64]);
    return Fr::interpret(&hash_buf);
}

pub fn hashBufferToFr<'a>(prefix: &'a str, buf: &[u8; 64]) -> Fr {
    let mut input_buf = Vec::new();
    input_buf.extend_from_slice(prefix.as_bytes());
    input_buf.extend_from_slice(buf);

    let sha2_digest = sha512::hash(&input_buf.as_slice());

    let mut hash_buf: [u8; 64] = [0; 64];
    hash_buf.copy_from_slice(&sha2_digest[0..64]);
    return Fr::interpret(&hash_buf);
}

//pub fn hashStrToFr(x: &str) -> Fr {
//    // TODO: change to serde (instead of rustc_serialize)
//    let sha2_digest = sha512::hash(x.as_slice());
//
//    let mut hash_buf: [u8; 64] = [0; 64];
//    hash_buf.copy_from_slice(&sha2_digest[0..64]);
//    return Fr::interpret(&hash_buf);
//}

fn convertToFr(input_buf: &Vec<u8>) -> Fr {
    // hash the inputs via SHA256
    let sha2_digest = sha512::hash(input_buf.as_slice());
    // println!("hash: {:?}", sha2_digest);
    // let h = format!("{:x}", HexSlice::new(&sha2_digest));
    let mut hash_buf: [u8; 64] = [0; 64];
    hash_buf.copy_from_slice(&sha2_digest[0..64]);
    return Fr::interpret(&hash_buf);
}

fn convertStrToFr<'a>(input: &'a str) -> Fr {
    let mut input_buf = Vec::new();
    input_buf.extend_from_slice(input.as_bytes());
    return convertToFr(&input_buf);
}

// refund message
#[derive(Clone)]
pub struct RefundMessage<'a> {
    pub msgtype: &'a str, // purpose type of message
    pub cid: Fr, // channel identifier
    pub wpk: secp256k1::PublicKey,
    pub balance: usize, // the balance
    pub r: Option<&'a Fr>, // randomness from customer wallet
    pub rt: Option<&'a clsigs::SignatureD> // refund token
}

impl<'a> RefundMessage<'a> {
    pub fn new(_msgtype: &'a str, _cid: Fr, _wpk: secp256k1::PublicKey,
               _balance: usize, _r: Option<&'a Fr>, _rt: Option<&'a clsigs::SignatureD>) -> RefundMessage<'a> {
        RefundMessage {
            msgtype: _msgtype, cid: _cid, wpk: _wpk, balance: _balance, r: _r, rt: _rt
        }
    }

    pub fn hash(&self) -> Vec<Fr> {
        let mut v: Vec<Fr> = Vec::new();
        let mut input_buf = Vec::new();
        input_buf.extend_from_slice(self.msgtype.as_bytes());
        v.push(convertToFr(&input_buf));

        v.push(self.cid.clone());

        v.push(hashPubKeyToFr(&self.wpk));

        // encoee the balance as a hex string
        let b = format!("{:x}", self.balance);
        let mut b_buf = Vec::new();
        b_buf.extend_from_slice(b.as_bytes());
        v.push(convertToFr(&b_buf));

        //let r_vec: Vec<u8> = encode(&self.r, Infinite).unwrap();
        if (!self.r.is_none()) {
            v.push(self.r.unwrap().clone());
        }

        if (!self.rt.is_none()) {
            let rt = self.rt.unwrap();
            v.push(rt.hash(self.msgtype));
        }

        return v;
    }
}

#[derive(Clone)]
pub struct RevokedMessage<'a> {
    pub msgtype: &'a str,
    pub wpk: secp256k1::PublicKey,
    pub sig: Option<Vec<u8>> // represents revocation token serialized compact bytes
}

impl<'a> RevokedMessage<'a> {
    pub fn new(_msgtype: &'a str, _wpk: secp256k1::PublicKey, _sig: Option<Vec<u8>>) -> RevokedMessage<'a> {
        RevokedMessage {
            msgtype: _msgtype, wpk: _wpk, sig: _sig
        }
    }

    pub fn hash(&self) -> Vec<Fr> {
        let mut v: Vec<Fr> = Vec::new();
        let mut input_buf = Vec::new();
        input_buf.extend_from_slice(self.msgtype.as_bytes());
        v.push(convertToFr(&input_buf));

        v.push(hashPubKeyToFr(&self.wpk));

        if (!self.sig.is_none()) {
            // TODO: make sure we can call hashBufferToFr with sig
            // v.push(hashBufferToFr(self.msgtype, self.sig.unwrap()));
        }
        return v;
    }

    // return a message digest (32-bytes)
    pub fn hash_to_slice(&self) -> [u8; 32] {
        let mut input_buf = Vec::new();
        input_buf.extend_from_slice(self.msgtype.as_bytes());
        input_buf.extend_from_slice(&self.wpk.serialize_uncompressed());
        let sha2_digest = sha512::hash(input_buf.as_slice());
        // println!("hash: {:?}", sha2_digest);
        // let h = format!("{:x}", HexSlice::new(&sha2_digest));
        let mut hash_buf: [u8; 32] = [0; 32];
        hash_buf.copy_from_slice(&sha2_digest[0..32]);
        return hash_buf;
    }
}

////////////////////////////////// NIZKP //////////////////////////////////

//pub mod unidirectional {
//    use std::fmt;
//    use rand;
//    use bn::{Group, Fr};
//    use sym;
//    use commit_scheme;
//    use clsigs;
//    use Message;
//    use sodiumoxide::randombytes;
//
//    pub struct PublicParams {
//        cm_mpk: commit_scheme::PublicKey,
//        cl_mpk: clsigs::PublicParams,
//        l_bits: i32
//        // TODO: add NIZK proof system pub params
//    }
//
//    pub struct ChannelToken {
//        w_com: commit_scheme::Commitment,
//        pk: clsigs::PublicKey
//    }
//
//    pub struct CustSecretKey {
//        sk: clsigs::SecretKey, // the secret key for the signature scheme (Is it possible to make this a generic field?)
//        k1: Fr, // seed 1 for PRF
//        k2: Fr, // seed 2 for PRF
//        r: Fr, // random coins for commitment scheme
//        balance: i32, // the balance for the user
//        ck_vec: Vec<sym::SymKey>
//    }
//
//    pub struct MerchSecretKey {
//        sk: clsigs::SecretKey,
//        balance: i32
//    }
//
//    pub struct InitCustomerData {
//        T: ChannelToken,
//        csk: CustSecretKey
//    }
//
//    pub struct InitMerchantData {
//        T: clsigs::PublicKey,
//        csk: MerchSecretKey
//    }
//
//    pub fn setup() -> PublicParams {
//        // TODO: provide option for generating CRS parameters
//        let cm_pk = commit_scheme::setup();
//        let cl_mpk = clsigs::setup();
//        let l = 256;
//        // let nizk = "nizk proof system";
//        let pp = PublicParams { cm_mpk: cm_pk, cl_mpk: cl_mpk, l_bits: l };
//        return pp;
//    }
//
//    pub fn keygen(pp: &PublicParams) -> clsigs::KeyPair {
//        // TODO: figure out what we need from public params to generate keys
//        println!("Run Keygen...");
//        let keypair = clsigs::keygen(&pp.cl_mpk);
//        return keypair;
//    }
//
//    pub fn init_customer(pp: &PublicParams, b0_customer: i32, keypair: &clsigs::KeyPair) -> InitCustomerData {
//        println!("Run Init customer...");
//        sym::init();
//        let rng = &mut rand::thread_rng();
//        // pick two distinct seeds
//        let l = 256;
//        let k1 = Fr::random(rng);
//        let k2 = Fr::random(rng);
//        let r = Fr::random(rng);
//        let msg = Message::new(keypair.sk, k1, k2, b0_customer).hash();
//
//        let mut ck_vec: Vec<sym::SymKey> = Vec::new();
//        // generate the vector ck of sym keys
//        for i in 1 .. b0_customer {
//            let ck = sym::keygen(l);
//            ck_vec.push(ck);
//        }
//        let w_com = commit_scheme::commit(&pp.cm_mpk, msg, Some(r));
//        let t_c = ChannelToken { w_com: w_com, pk: keypair.pk };
//        let csk_c = CustSecretKey { sk: keypair.sk, k1: k1, k2: k2, r: r, balance: b0_customer, ck_vec: ck_vec };
//        return InitCustomerData { T: t_c, csk: csk_c };
//    }
//
//    pub fn init_merchant(pp: &PublicParams, b0_merchant: i32, keypair: &clsigs::KeyPair) -> InitMerchantData {
//        println!("Run Init merchant...");
//        let csk_m = MerchSecretKey { sk: keypair.sk, balance: b0_merchant };
//        return InitMerchantData { T: keypair.pk, csk: csk_m };
//    }
//
//    // TODO: requires NIZK proof system
//    pub fn establish_customer(pp: &PublicParams, t_m: &clsigs::PublicKey, csk_c: &CustSecretKey) {
//        println ! ("Run establish_customer algorithm...");
//        // set sk_0 to random bytes of length l
//        // let sk_0 = random_bytes(pp.l);
//        let buf_len: usize = pp.l_bits as usize;
//        let mut sk0 = vec![0; buf_len];
//        randombytes::randombytes_into(&mut sk0);
//
//        let pi1 = create_nizk_proof_one(csk_c.sk, csk_c.k1, csk_c.k2, );
//    }
//}

pub mod bidirectional {
    use std::fmt;
    use rand;
    use bn::{Group, Fr, G1, G2, Gt};
    use sym;
    use commit_scheme;
    use clsigs;
    use Message;
    use sodiumoxide::randombytes;
    use secp256k1; // ::{Secp256k1, PublicKey, SecretKey};
    use RefundMessage;
    use RevokedMessage;
    use hashPubKeyToFr;
    use hashBufferToFr;
    use debug_elem_in_hex;
    use debug_gt_in_hex;
    use convertToFr;
    use convertStrToFr;

    fn print_secret_vector(x: &Vec<Fr>) {
        for i in 0 .. x.len() {
            let msg = format!("x[{}] => ", i);
            debug_elem_in_hex(&msg, &x[i]);
        }
    }

    fn print_public_bases_vector(g: &Vec<Gt>) {
        for i in 0 .. g.len() {
            let msg = format!("g[{}] => ", i);
            debug_gt_in_hex(&msg, &g[i]);
        }
    }

    pub struct PublicParams {
        cl_mpk: clsigs::PublicParams,
        l: usize // messages for committment
    }

    pub struct ChannelToken {
        w_com: commit_scheme::Commitment,
        pk: clsigs::PublicKeyD
    }

    // TODO: add display method to print structure (similar to Commitment)
    pub struct CustomerWallet {
        sk: clsigs::SecretKeyD, // the secret key for the signature scheme (Is it possible to make this a generic field?)
        cid: Fr, // channel Id
        wpk: secp256k1::PublicKey, // signature verification key
        wsk: secp256k1::SecretKey, // signature signing key
        r: Fr, // random coins for commitment scheme
        pub balance: i32, // the balance for the user
        signature: Option<clsigs::SignatureD>,
        refund_token: Option<clsigs::SignatureD>
    }

    // TODO: add display method to print structure (similar to Commitment)
    pub struct MerchSecretKey {
        sk: clsigs::SecretKeyD, // merchant signing key
        pub balance: i32
    }

    pub struct InitCustomerData {
        pub T: ChannelToken,
        pub csk: CustomerWallet,
        pub bases: Vec<G2>,
    }

    pub struct InitMerchantData {
        pub T: clsigs::PublicKeyD,
        pub csk: MerchSecretKey,
        pub bases: Vec<G2>
    }

    // TODO: add method to display contents of the channel state
    // should include contents of the channel state
    pub struct ChannelState<'a> {
        //pub pub_keys: HashMap,
        pub name: &'a str,
        pub cid: Fr,
        pub pay_init: bool,
        pub channel_established: bool
    }

    pub struct ChannelClosure_C<'a> {
        message: RefundMessage<'a>,
        signature: clsigs::SignatureD
    }

    pub struct ChannelClosure_M<'a> {
        message: RevokedMessage<'a>,
        signature: clsigs::SignatureD
    }

    pub struct PaymentProof {
        proof2a: clsigs::ProofCV, // proof of committed values in new wallet
        proof2b: clsigs::ProofVS, // proof of knowledge of wallet signature
        balance: i32, // balance increment
        w_com: commit_scheme::Commitment, // commitment for new wallet
        wpk: secp256k1::PublicKey, // verification key for old wallet
        wallet_sig: clsigs::SignatureD // blinded signature for old wallet
        // TODO: add proof2c: range proof that balance - balance_inc is between (0, val_max)
    }

    pub struct RevokeToken<'a> {
        message: RevokedMessage<'a>,
        signature: secp256k1::Signature
    }

    pub fn setup() -> PublicParams {
        // TODO: provide option for generating CRS parameters
        let cl_mpk = clsigs::setupD();
        let l = 4;
        // let nizk = "nizk proof system";
        let pp = PublicParams { cl_mpk: cl_mpk, l: l };
        return pp;
    }

    pub fn keygen(pp: &PublicParams) -> clsigs::KeyPairD {
        // TODO: figure out what we need from public params to generate keys
        println!("Run Keygen...");
        let keypair = clsigs::keygenD(&pp.cl_mpk, pp.l);
        return keypair;
    }

    fn generate_channel_id() -> Fr {
        let rng = &mut rand::thread_rng();
        return Fr::random(rng);
    }

    pub fn generate_commit_setup(pp: &PublicParams, pk: &clsigs::PublicKeyD) -> commit_scheme::CSParams {
        let g2 = pp.cl_mpk.g2.clone();
        let bases = pk.Z2.clone();
        let cm_csp = commit_scheme::setup(pp.l, bases, g2);
        return cm_csp;
    }

    pub fn init_customer<'a>(pp: &PublicParams, channel: &ChannelState, b0_customer: i32,
                         cm_csp: &commit_scheme::CSParams, keypair: &clsigs::KeyPairD) -> InitCustomerData {
        println!("Run Init customer...");
        let rng = &mut rand::thread_rng();
        // generate verification key and signing key (for wallet)
        let mut schnorr = secp256k1::Secp256k1::new();
        schnorr.randomize(rng);
        let (wsk, wpk) = schnorr.generate_keypair(rng).unwrap();
        let h_wpk = hashPubKeyToFr(&wpk);
        // convert balance into Fr
        let b0 = Fr::from_str(b0_customer.to_string().as_str()).unwrap();
        // randomness for commitment
        let r = Fr::random(rng);
        // retreive the channel id
        let cid = channel.cid.clone();

        let mut x: Vec<Fr> = Vec::new();
        x.push(r); // set randomness for commitment
        x.push(cid);
        x.push(h_wpk);
        x.push(b0);

        let w_com = commit_scheme::commit(&cm_csp,  &x, r);
        let t_c = ChannelToken { w_com: w_com, pk: keypair.pk.clone() };
        let csk_c = CustomerWallet { sk: keypair.sk.clone(), cid: cid, wpk: wpk, wsk: wsk,
                                    r: r, balance: b0_customer, signature: None,
                                    refund_token: None };
        return InitCustomerData { T: t_c, csk: csk_c, bases: cm_csp.pub_bases.clone() };
    }

    pub fn init_merchant(pp: &PublicParams, b0_merchant: i32, keypair: &clsigs::KeyPairD) -> InitMerchantData {
        println!("Run Init merchant...");
        let cm_csp = generate_commit_setup(&pp, &keypair.pk);
        let csk_m = MerchSecretKey { sk: keypair.sk.clone(), balance: b0_merchant };
        return InitMerchantData { T: keypair.pk.clone(), csk: csk_m, bases: cm_csp.pub_bases };
    }

    pub fn init_channel<'a>(name: &'a str) -> ChannelState<'a> {
        let cid = generate_channel_id();
        // TODO: add hashmap definition to store wpks and optionally store rev tokens?
        return ChannelState { name: name, cid: cid, channel_established: false, pay_init: false }
    }

    //// begin of establish channel protocol
    pub fn establish_customer_phase1(pp: &PublicParams, c_data: &InitCustomerData, m_data: &InitMerchantData) -> clsigs::ProofCV {
        println!("Run establish_customer algorithm...");
        // obtain customer init data
        let t_c = &c_data.T;
        let csk_c = &c_data.csk;
        let pub_bases = &m_data.bases;

        let h_wpk = hashPubKeyToFr(&csk_c.wpk);
        let b0 = Fr::from_str(csk_c.balance.to_string().as_str()).unwrap();
        // collect secrets
        let mut x: Vec<Fr> = Vec::new();
        x.push(t_c.w_com.r); // set randomness used to generate commitment
        x.push(csk_c.cid);
        x.push(h_wpk);
        x.push(b0);
        println!("establish_customer_phase1 - secrets for original wallet");
        print_secret_vector(&x);

        // generate proof of knowledge for committed values
        let proof_1 = clsigs::bs_gen_nizk_proof(&x, &pub_bases, t_c.w_com.c);
        return proof_1;
    }

    // the merchant calls this method after obtaining proof from the customer
    pub fn establish_merchant_phase2(pp: &PublicParams, state: &mut ChannelState, m_data: &InitMerchantData,
                                     proof: &clsigs::ProofCV) -> clsigs::SignatureD {
        // verifies proof and produces
        let wallet_sig = clsigs::bs_check_proof_and_gen_signature(&pp.cl_mpk, &m_data.csk.sk, &proof);
        state.channel_established = true;
        return wallet_sig;
    }

    pub fn establish_customer_final(pp: &PublicParams, pk_m: &clsigs::PublicKeyD, w: &mut CustomerWallet, sig: clsigs::SignatureD) -> bool {
        if w.signature.is_none() {
            let mut x: Vec<Fr> = Vec::new();
            x.push(w.r.clone());
            x.push(w.cid.clone());
            x.push(hashPubKeyToFr(&w.wpk));
            x.push(Fr::from_str(w.balance.to_string().as_str()).unwrap());

            println!("establish_customer_final - print secrets");
            print_secret_vector(&x);

            assert!(clsigs::verifyD(&pp.cl_mpk, &pk_m, &x, &sig));
            w.signature = Some(sig);
            return true;
        }
        // must be an old wallet
        return false;
    }
    ///// end of establish channel protocol

    ///// begin of pay protocol
    pub fn payment_by_customer_phase1(pp: &PublicParams, T: &ChannelToken, pk_m: &clsigs::PublicKeyD,
                                      old_w: &CustomerWallet, balance_increment: i32) -> (CustomerWallet, PaymentProof) {
        println!("Run pay algorithm by Customer - phase 1.");
        // get balance, keypair, commitment randomness and wallet sig
        let rng = &mut rand::thread_rng();

        let B = old_w.balance;
        let old_wpk = &old_w.wpk;
        let old_wsk = &old_w.wsk;
        let old_r = &old_w.r;
        let old_wallet_sig = &old_w.signature;

        // generate new keypair
        let mut schnorr = secp256k1::Secp256k1::new();
        schnorr.randomize(rng);
        let (wsk, wpk) = schnorr.generate_keypair(rng).unwrap();
        let h_wpk = hashPubKeyToFr(&wpk);

        // new sample randomness r'
        let r_pr = Fr::random(rng);

//        let g2 = pp.cl_mpk.g2.clone();
//        let bases = pk.Z2.clone();
//        let cm_csp = commit_scheme::setup(pp.l, bases, g2);
        // retrieve the commitment scheme parameters based on merchant's PK
        let cm_csp = generate_commit_setup(&pp, &pk_m);

        let cid = old_w.cid.clone();
        // retrieve old balance
        let old_balance = Fr::from_str(B.to_string().as_str()).unwrap();
        // convert balance into Fr (B - e)
        let updated_balance = B - balance_increment;
        let updated_balance_pr = Fr::from_str(updated_balance.to_string().as_str()).unwrap();

        let mut new_wallet_sec: Vec<Fr> = Vec::new();
        new_wallet_sec.push(r_pr); // set randomness for commitment
        new_wallet_sec.push(cid);
        new_wallet_sec.push(h_wpk);
        new_wallet_sec.push(updated_balance_pr);

        let w_com = commit_scheme::commit(&cm_csp, &new_wallet_sec, r_pr);

        // generate proof of knowledge for committed values
//        let mut pub_bases = pk.Z2.clone();
//        pub_bases.insert(0, g2);
        let proof_cv = clsigs::bs_gen_nizk_proof(&new_wallet_sec, &cm_csp.pub_bases, w_com.c);

        // generate proof of knowledge of valid signature on previous wallet signature
        let wallet_sig = old_wallet_sig.clone().unwrap();

        let old_h_wpk = hashPubKeyToFr(&old_wpk);

        // added the blinding factor to list of secrets
        let mut old_x: Vec<Fr> = Vec::new();
        old_x.push(old_r.clone()); // set randomness for commitment
        old_x.push(cid);
        old_x.push(old_h_wpk);
        old_x.push(old_balance);

        let blind_sigs = clsigs::prover_generate_blinded_sig(&wallet_sig);
        let common_params = clsigs::gen_common_params(&pp.cl_mpk, &pk_m, &wallet_sig);

        //println!("payment_by_customer_phase1 - secrets for old wallet");
        //print_secret_vector(&old_x);

        let proof_vs = clsigs::vs_gen_nizk_proof(&old_x, &common_params, common_params.vs);
        //clsigs::vs_verify_blind_sig(&pp.cl_mpk, &pk, &proof_vs, &blind_sigs);
        let payment_proof = PaymentProof {
                                proof2a: proof_cv, // proof of knowledge for committed values
                                proof2b: proof_vs, // proof of knowledge of signature on old wallet
                                w_com: w_com,
                                balance: balance_increment, // epsilon - increment/decrement
                              //w_com_pr: w_com_pr, // old commitment minus wpk
                                wpk: old_wpk.clone(), // showing public key for old wallet
                                wallet_sig: blind_sigs // blinded signature for old wallet
                            };
        let csk_c = CustomerWallet { sk: old_w.sk.clone(), cid: cid, wpk: wpk, wsk: wsk,
                            r: r_pr, balance: updated_balance, signature: None,
                            refund_token: None };
        return (csk_c, payment_proof);
    }

    // NOTE regarding balance increments
    // a positive increment => increment merchant balance, and decrement customer balance
    // a negative increment => decrement merchant balance, and increment customer balance
    pub fn payment_by_merchant_phase1(pp: &PublicParams, proof: &PaymentProof, m_data: &InitMerchantData) -> clsigs::SignatureD {
        println!("Run pay algorithm by Merchant - phase 2");
        let blind_sigs = &proof.wallet_sig;
        let proof_cv = &proof.proof2a;
        let proof_vs = &proof.proof2b;
        // get merchant keypair
        let pk_m = &m_data.T;
        let sk_m = &m_data.csk.sk;

        // let's first confirm that proof of knowledge of signature on old wallet is valid
        let proof_vs_old_wallet = clsigs::vs_verify_blind_sig(&pp.cl_mpk, &pk_m, &proof_vs, &blind_sigs);
        if proof_vs_old_wallet {
            println!("Yay! Proof of knowledge of signature is valid!");

        } else {
            panic!("FAILURE! Verification failure for old wallet signature !");
        }

        // verify the proof of knowledge for committed values in new wallet
        //let new_wallet_sig = clsigs::bs_check_proof_and_gen_signature(&pp.cl_mpk, &sk_m, &proof_cv);
        if clsigs::bs_verify_nizk_proof(&proof_cv) {
            // generate refund token on new wallet
            let i = pk_m.Z2.len()-1;
            let C_refund = proof_cv.C + (pk_m.Z2[i] * convertStrToFr("refund"));
            // generating partially blind signature on refund || wpk' || B - e
            let rt_w = clsigs::bs_compute_blind_signature(&pp.cl_mpk, &sk_m, C_refund, proof_cv.num_secrets + 1); // proof_cv.C
            println!("Yay! Proof of knowledge of commitment on new wallet is valid");
            return rt_w;
        }

        // generate signature for new wallet with updated balance

        // let's update the merchant's wallet balance now
        panic!("Failed verification!");
    }

    pub fn payment_by_customer_phase2<'a>(pp: &PublicParams, old_w: &CustomerWallet, new_w: &CustomerWallet,
                                      pk_m: &clsigs::PublicKeyD, rt_w: &clsigs::SignatureD) -> RevokeToken<'a> {

        // (1) verify the rt_w against the new wallet contents
        let mut x: Vec<Fr> = Vec::new();
        x.push(new_w.r.clone());
        x.push(new_w.cid.clone());
        x.push(hashPubKeyToFr(&new_w.wpk));
        x.push(Fr::from_str(new_w.balance.to_string().as_str()).unwrap());
        x.push(convertStrToFr("refund"));

        let is_rt_w_valid = clsigs::verifyD(&pp.cl_mpk, &pk_m, &x, &rt_w);

        if (is_rt_w_valid) {
            println!("Refund token is valid against the new wallet!");
            let mut schnorr = secp256k1::Secp256k1::new();
            let rm = RevokedMessage::new("revoked", old_w.wpk, None);
            let msg = secp256k1::Message::from_slice(&rm.hash_to_slice()).unwrap();
            // msg = "revoked"|| old_wpk (for old wallet)
            let rv_w = schnorr.sign(&msg, &old_w.wsk);

            // return the revocation token
            return RevokeToken { message: rm, signature: rv_w.unwrap() };
        }
        panic!("FAIL: Merchant did not provide a valid refund token!");
    }

    pub fn payment_by_merchant_phase2(pp: &PublicParams, proof: &PaymentProof, m_data: &mut InitMerchantData, rv: &RevokeToken) -> clsigs::SignatureD {
        let proof_cv = &proof.proof2a;
        let sk_m = &m_data.csk.sk;
        let schnorr = secp256k1::Secp256k1::new();
        let msg = secp256k1::Message::from_slice(&rv.message.hash_to_slice()).unwrap();
        // verify that the revocation token is valid
        let is_rv_valid = schnorr.verify(&msg, &rv.signature, &proof.wpk).is_ok();
        // TODO: check that we are in the proper state
        if clsigs::bs_verify_nizk_proof(&proof_cv) && is_rv_valid {
            let new_wallet_sig = clsigs::bs_compute_blind_signature(&pp.cl_mpk, &sk_m, proof_cv.C, proof_cv.num_secrets);
            m_data.csk.balance += proof.balance;
            return new_wallet_sig;
        }

        panic!("FAIL: Customer did not provide valid revocation token!");
    }

    pub fn payment_by_customer_final(pp: &PublicParams, pk_m: &clsigs::PublicKeyD,
                                     c_data: &mut InitCustomerData,
                                     mut new_w: CustomerWallet, sig: clsigs::SignatureD) -> bool {
        if new_w.signature.is_none() {
            let mut x: Vec<Fr> = Vec::new();
            x.push(new_w.r.clone());
            x.push(new_w.cid.clone());
            x.push(hashPubKeyToFr(&new_w.wpk));
            x.push(Fr::from_str(new_w.balance.to_string().as_str()).unwrap());

            println!("payment_by_customer_final - print secrets");
            print_secret_vector(&x);

            assert!(clsigs::verifyD(&pp.cl_mpk, &pk_m, &x, &sig));
            new_w.signature = Some(sig);
            c_data.csk = new_w;
            return true;
        }
        // must be an old wallet
        return false;
    }

    ///// end of pay protocol

    // for customer => on input a wallet w, it outputs a customer channel closure message rc_c
    pub fn customer_refund<'a>(pp: &PublicParams, state: &ChannelState, m_data: &InitMerchantData,
                  c_data: &'a InitCustomerData) -> ChannelClosure_C<'a> {
        println!("Run Refund...");
        let m;
        let w = &c_data.csk; // get wallet
        let balance = w.balance as usize;
        if !state.pay_init {
            // pay protocol not invoked so take the balane
            m = RefundMessage::new("refundUnsigned", state.cid, w.wpk, balance, Some(&w.r), None);
        } else {
            // if channel has already been activated, then take unspent funds
            m = RefundMessage::new("refundToken", state.cid, w.wpk, balance, None, w.refund_token.as_ref());
        }

        // generate signature on the balance/channel id, etc to obtain funds back
        let m_vec = m.hash();
        let sigma = clsigs::signD(&pp.cl_mpk, &w.sk, &m_vec);
        return ChannelClosure_C { message: m, signature: sigma };
    }

    fn exist_in_merchant_state(s: &ChannelState, wpk: &secp256k1::PublicKey, sig_rev: &clsigs::SignatureD) -> bool {
        // TODO: check the database for the fingerprint for the wpk + sig?
        return true;
    }

    fn update_merchant_state(s: &mut ChannelState, wpk: &secp256k1::PublicKey) -> bool {
        // TODO: implement this method to update channel state db with current public key hash?
        return true;
    }

    // for merchant => on input the merchant's current state S_old and a customer channel closure message,
    // outputs a merchant channel closure message rc_m and updated merchant state S_new
    pub fn merchant_refute<'a>(pp: &PublicParams, T_c: &ChannelToken, m_data: &InitMerchantData,
                  state: &mut ChannelState, rc_c: ChannelClosure_C<'a>)  -> Option<ChannelClosure_M<'a>> {
        println!("Run Refute...");

        let is_valid = clsigs::verifyD(&pp.cl_mpk, &T_c.pk, &rc_c.message.hash(), &rc_c.signature);
        if is_valid {
            let wpk = rc_c.message.wpk;
            let rv_token = rc_c.signature; // TODO: change to \sigma_rev
            let balance = rc_c.message.balance;
            if exist_in_merchant_state(&state, &wpk, &rv_token) {
                // let mut s = Secp256k1::new();
                // let sig = rv_token.serialize_compact(&s);
                // TODO: convert rv_w into a slice
                let rm = RevokedMessage::new("revoked", wpk, None);
                // sign the revoked message
                let signature = clsigs::signD(&pp.cl_mpk, &m_data.csk.sk, &rm.hash());
                return Some(ChannelClosure_M { message: rm, signature: signature });
            } else {
                // update state to include the user's wallet key
                assert!(update_merchant_state(state, &wpk));
                return None;
            }
        } else {
            panic!("Signature on customer closure message is invalid!");
        }
    }

    // on input th ecustmomer and merchant channel tokens T_c, T_m
    // along with closure messages rc_c, rc_m
    pub fn resolve<'a>(pp: &PublicParams, c: &InitCustomerData, m: &InitMerchantData,         // cust and merch
                   rc_c: Option<ChannelClosure_C<'a>>, rc_m: Option<ChannelClosure_M<'a>>) -> (i32, i32) {
        println!("Run Resolve...");
        let total_balance = c.csk.balance + m.csk.balance;
        if (rc_c.is_none() && rc_m.is_none()) {
            panic!("resolve - Did not specify channel closure messages for either customer or merchant!");
        }

        if rc_c.is_none() {
            // customer did not specify channel closure message
            return (0, total_balance);
        }

        // TODO: use matching instead
//        match rc_c.unwrap() {
//            Some(v) => foo,
//            _ => return (0, 0);
//        }

        let pk_c = &c.T.pk;
        let pk_m = &m.T;

        let rc_cust = rc_c.unwrap();
        let rcc_valid = clsigs::verifyD(&pp.cl_mpk, &pk_c, &rc_cust.message.hash(), &rc_cust.signature);
        if !rcc_valid {
            panic!("resolve - rc_c signature is invalid!");
        }
        let msg = &rc_cust.message;
        let w_com = &c.T.w_com;

        if msg.msgtype == "refundUnsigned" {
            // assert the validity of the w_com
            let bases = c.bases.clone();
            let g2 = pp.cl_mpk.g2.clone();
            let cm_csp = commit_scheme::setup(pp.l, bases, g2);
            let h_wpk = hashPubKeyToFr(&c.csk.wpk);
            // convert balance into Fr
            let balance = Fr::from_str(c.csk.balance.to_string().as_str()).unwrap();

            let mut x: Vec<Fr> = Vec::new();
            x.push(w_com.r); // Token if decommit is valid
            x.push(c.csk.cid);
            x.push(h_wpk);
            x.push(balance);

            // check that w_com is a valid commitment
            if !commit_scheme::decommit(&cm_csp, &w_com, &x) {
                // if this fails, then customer gets 0 and merchant gets full channel balance
                return (0, total_balance);
            }
        } else if msg.msgtype == "refundToken" {
            // TODO: check that rt_w is a valid refund token on wpk and balance
            let rt_w = &rc_cust.signature; // TODO: replace with real rt_w
            let rt_valid = clsigs::verifyD(&pp.cl_mpk, &pk_c, &msg.hash(), &rt_w);
            if !rt_valid {
                // refund token signature not valid, so pay full channel balance to merchant
                return (0, total_balance)
            }
        }

        if !rc_m.is_none() {
            let rc_merch = rc_m.unwrap();
            let refute_valid = clsigs::verifyD(&pp.cl_mpk, &pk_m, &rc_merch.message.hash(), &rc_merch.signature);
            if !refute_valid {
                // refutation si invalid, so return customer balance and merchant balanace - claimed value
                let claimed_value = 0; // TODO: figure out where this value comes from
                return (c.csk.balance, m.csk.balance - claimed_value); // TODO: ensure merchant balance > 0
            } else {
                // if refutation is valid
                return (0, total_balance);
            }
        }

        panic!("resolve - Did not specify channel closure messages for either customer or merchant!");
    }
}
