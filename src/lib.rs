extern crate bn;
extern crate rand;
extern crate bincode;
extern crate sodiumoxide;
//extern crate test;

use std::fmt;
use std::str;
use std::default;
use bn::{Group, Fr, G1, G2, Gt, pairing};
use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::{encode, decode};
use sodiumoxide::randombytes;
use sodiumoxide::crypto::hash::sha512;

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

////////////////////////////////// CL Sigs /////////////////////////////////////

// refund message
#[derive(Clone)]
pub struct RefundMessage<'a> {
    prefix: &'a str, // string prefix for the prefix
    c_id: Fr, // uniquely identifies the
    index: i32, // index
    // ck: Fr, // TODO: l-bit key (from SymKeyEnc)
}

impl<'a> RefundMessage<'a> {
    pub fn new(_c_id: Fr, _index: i32) -> RefundMessage<'a> {
        RefundMessage {
            prefix: "refund", c_id: _c_id, index: _index,
        }
    }

    pub fn hash(&self) -> Fr {
        let mut input_buf = Vec::new();
        input_buf.extend_from_slice(self.prefix.as_bytes());
        let c_id_vec: Vec<u8> = encode(&self.c_id, Infinite).unwrap();
        // encode cId in the vector
        input_buf.extend(c_id_vec);
        // encoee the balance as a hex string
        let b = format!("{:x}", self.index);
        input_buf.extend_from_slice(b.as_bytes());
        // TODO: add the ck vector (l-bit key)
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

// spend message
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

#[derive(Copy, Clone)]
pub struct Proof {
    T: G1,
    c: Fr,
    s1: Fr,
    s2: Fr
}

pub fn hash(g: &G1, h: &G1, X: &G1, Y: &G1, T: &Gt) -> Fr {
    let g_vec: Vec<u8> = encode(&g, Infinite).unwrap();

    // TODO: fix this
    return Fr::from_str("1234567890").unwrap();
}

pub fn hashG1ToFr(x: &G1) -> Fr {
    // TODO: change to serde (instead of rustc_serialize)
    let x_vec: Vec<u8> = encode(&x, Infinite).unwrap();
    let sha2_digest = sha512::hash(x_vec.as_slice());

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


//pub fn create_nizk_proof_one(pp: &PublicParams, pk: &clsigs::PublicKeyD, sk: &clsigs::SecretKeyD) -> Proof {
//    let rng = &mut rand::thread_rng();
//
//    let t1 = Fr::random(rng);
//    let t2 = Fr::random(rng);
//
//    let T = (pk.g * t1) + (pk.h * t2);
//
//    let c = hash(pp.g, pp.h, pk.X, pk.Y, T);
//
//    let s1 = (sk.x * c) + t1;
//    let s2 = (sk.y * c) + t2;
//
//    return Proof { T: T, c: c, s1: s1, s2: s2 };
//}

pub fn verify_nizk_proof_one(proof: &Proof) -> bool {
   // how do we verify the proof?
    return true;
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
    use bn::{Group, Fr, G1};
    use sym;
    use commit_scheme;
    use clsigs;
    use Message;
    use hashG1ToFr;
    use sodiumoxide::randombytes;

    pub struct PublicParams {
        cm_mpk: commit_scheme::PublicParams,
        cl_mpk: clsigs::PublicParams,
        l_bits: i32
        // TODO: add NIZK proof system pub params
    }

    pub struct ChannelToken {
        w_com: commit_scheme::Commitment,
        pk: clsigs::PublicKeyD
    }

    pub struct CustSecretKey {
        sk: clsigs::SecretKeyD, // the secret key for the signature scheme (Is it possible to make this a generic field?)
        cid: Fr, // channel Id
        wpk: G1, // signature verification key
        wsk: Fr, // signature private key
        r: Fr, // random coins for commitment scheme
        balance: i32, // the balance for the user
        ck_vec: Vec<sym::SymKey>
    }

    pub struct MerchSecretKey {
        sk: clsigs::SecretKeyD,
        balance: i32
    }

    pub struct InitCustomerData {
        T: ChannelToken,
        csk: CustSecretKey
    }

    pub struct InitMerchantData {
        T: clsigs::PublicKeyD,
        csk: MerchSecretKey
    }

    pub fn setup() -> PublicParams {
        // TODO: provide option for generating CRS parameters
        let cm_pp = commit_scheme::setup();
        let cl_mpk = clsigs::setupD();
        let l = 256;
        // let nizk = "nizk proof system";
        let pp = PublicParams { cm_mpk: cm_pp, cl_mpk: cl_mpk, l_bits: l };
        return pp;
    }

    pub fn keygen(pp: &PublicParams) -> clsigs::KeyPairD {
        // TODO: figure out what we need from public params to generate keys
        println!("Run Keygen...");
        let keypair = clsigs::keygenD(&pp.cl_mpk, 3);
        return keypair;
    }

    pub fn init_customer(pp: &PublicParams, channelId: Fr, b0_customer: i32, keypair: &clsigs::KeyPairD) -> InitCustomerData {
        println!("Run Init customer...");
        sym::init();
        let rng = &mut rand::thread_rng();
        // pick two distinct seeds
        let l = 256;
        // keygen for wallet
        let wsk = Fr::random(rng);
        let wpk = pp.cm_mpk.g2 * wsk;
        let h_wpk = hashG1ToFr(&wpk);
        let b0 = Fr::from_str(b0_customer.to_string().as_str()).unwrap();
        let r = Fr::random(rng);
        //let msg = Message::new(keypair.sk, k1, k2, b0_customer).hash();

        let mut ck_vec: Vec<sym::SymKey> = Vec::new();
        // generate the vector ck of sym keys
        for i in 1 .. b0_customer {
            let ck = sym::keygen(l);
            ck_vec.push(ck);
        }

        // TODO: hash (wpk) and convert b0_customer into Fr
        let w_com = commit_scheme::commit(&pp.cm_mpk, channelId, h_wpk, b0, Some(r));
        let t_c = ChannelToken { w_com: w_com, pk: keypair.pk.clone() };
        let csk_c = CustSecretKey { sk: keypair.sk.clone(), cid: channelId, wpk: wpk, wsk: wsk,
                                    r: r, balance: b0_customer, ck_vec: ck_vec };
        return InitCustomerData { T: t_c, csk: csk_c };
    }

    pub fn init_merchant(pp: &PublicParams, b0_merchant: i32, keypair: &clsigs::KeyPairD) -> InitMerchantData {
        println!("Run Init merchant...");
        let csk_m = MerchSecretKey { sk: keypair.sk.clone(), balance: b0_merchant };
        return InitMerchantData { T: keypair.pk.clone(), csk: csk_m };
    }

    // TODO: requires NIZK proof system
    pub fn establish_customer(pp: &PublicParams, t_m: &clsigs::PublicKeyD, csk_c: &CustSecretKey) {
        println ! ("Run establish_customer algorithm...");
        // set sk_0 to random bytes of length l
        // let sk_0 = random_bytes(pp.l);
        let buf_len: usize = pp.l_bits as usize;
        let mut sk0 = vec![0; buf_len];
        randombytes::randombytes_into(&mut sk0);

        //let pi1 = create_nizk_proof_one(csk_c.sk, csk_c.k1, csk_c.k2, );
    }

    // the merchant calls this method after obtaining
    pub fn estalibsh_merchant() {

    }

    // TODO: requires NIZK proof system calls
    pub fn pay_by_customer() {
        println!("Run pay algorithm by Customer - phase 1.");
    }

    pub fn pay_by_merchant() {
        println!("Run pay algorithm by Merchant - phase 1");
    }

//    pub fn refund(pp: &PublicParams, imd : &InitMerchantData, w: Wallet) {
//        println!("Run Refund...");
//    }
//
//    pub fn refute() {
//        println!("Run Refute...");
//    }
//
//    pub fn resolve() {
//        println!("Run Resolve...");
//    }
}
