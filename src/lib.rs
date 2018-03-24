extern crate bn;
extern crate rand;
extern crate bincode;
extern crate sodiumoxide;

use std::fmt;
use std::str;
use std::default;
use bn::{Group, Fr, G1, G2, pairing};
use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::{encode, decode};
use sodiumoxide::crypto::hash::sha512;

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

////////////////////////////////// CL Sigs /////////////////////////////////////

pub mod clsigs {
    use std::fmt;
    use std::str;
    use std::default;
    use rand;
    use bn::{Group, Fr, G1, G2, pairing};
    use debug_elem_in_hex;
    use bincode::SizeLimit::Infinite;
    use bincode::rustc_serialize::encode;
    use sodiumoxide::crypto::hash::sha512;

    pub struct PublicParams {
        g: G1
    }

    pub struct PublicKey {
        X: G1,
        Y: G1
    }

    impl fmt::Display for PublicKey {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let x_vec: Vec<u8> = encode(&self.X, Infinite).unwrap();
            let y_vec: Vec<u8> = encode(&self.Y, Infinite).unwrap();
            let mut x_s = String::new();
            for x in x_vec.iter() {
                x_s = format!("{}{:x}", x_s, x);
            }

            let mut y_s = String::new();
            for y in y_vec.iter() {
                y_s = format!("{}{:x}", y_s, y);
            }

            write!(f, "PK : (X=0x{}, Y=0x{})", x_s, y_s)
        }
    }

    pub struct SecretKey {
        x: Fr,
        y: Fr
    }

    pub struct KeyPair {
        pub sk: SecretKey,
        pub pk: PublicKey
    }

    pub struct Signature {
        a: G2,
        b: G2,
        c: G2
    }

    impl fmt::Display for Signature {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let a_vec: Vec<u8> = encode(&self.a, Infinite).unwrap();
            let b_vec: Vec<u8> = encode(&self.b, Infinite).unwrap();
            let c_vec: Vec<u8> = encode(&self.c, Infinite).unwrap();
            let mut a_s = String::new();
            for x in a_vec.iter() {
                a_s = format!("{}{:x}", a_s, x);
            }

            let mut b_s = String::new();
            for y in b_vec.iter() {
                b_s = format!("{}{:x}", b_s, y);
            }

            let mut c_s = String::new();
            for y in c_vec.iter() {
                c_s = format!("{}{:x}", c_s, y);
            }

            write!(f, "Signature : (\na = 0x{},\nb = 0x{},\nc = 0x{}\n)", a_s, b_s, c_s)
        }
    }

    #[derive(Clone)]
    pub struct Message {
        prefix: String, // the secret key for the signature scheme
        c_id: Fr, // uniquely identifies the
        index: i32, // index
        // ck: Fr, // TODO: l-bit key (from SymKeyEnc)
    }

    impl Message {
        pub fn new(_prefix: String, _c_id: Fr, _index: i32) -> Message {
            Message {
                prefix: _prefix, c_id: _c_id, index: _index,
            }
        }

        fn hash(&self) -> Fr {
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


    pub fn setup() -> PublicParams {
        let rng = &mut rand::thread_rng();
        let g = G1::random(rng);
        let mpk = PublicParams { g: g };
        return mpk;
    }

    pub fn keygen(mpk : &PublicParams) -> KeyPair {
        let rng = &mut rand::thread_rng();
        let x = Fr::random(rng);
        let y = Fr::random(rng);
        let sk = SecretKey { x: x, y: y };
        let pk = PublicKey { X: mpk.g * x,
                             Y: mpk.g * y
                            };
        return KeyPair { sk: sk, pk: pk }
    }

    pub fn sign(sk: &SecretKey, msg: &Message) -> Signature {
        let rng = &mut rand::thread_rng();
        let a = G2::random(rng);
        let m = msg.hash();
        let b = a * sk.y;
        let c = a * (sk.x + (m * sk.x * sk.y));
        let sig = Signature { a: a, b: b, c: c };
        return sig;
    }

    pub fn verify(mpk: &PublicParams, pk: &PublicKey, msg: &Message, sig: &Signature) -> bool {
        let m = msg.hash();
        let lhs1 = pairing(pk.Y, sig.a);
        let rhs1 = pairing(mpk.g, sig.b);
        let lhs2 = pairing(pk.X, sig.a) * (pairing(pk.X, sig.b).pow(m));
        let rhs2 = pairing(mpk.g, sig.c);
        return (lhs1 == rhs1) && (lhs2 == rhs2);
    }

}

////////////////////////////////// CL Sigs /////////////////////////////////////

////////////////////////////////// COMMITMENT //////////////////////////////////

pub mod commit_scheme {
    use std::fmt;
    use rand;
    use std::str;
    use std::default;
    use bn::{Group, Fr, G1};
    use debug_elem_in_hex;
    use bincode::SizeLimit::Infinite;
    use bincode::rustc_serialize::encode;
    use sodiumoxide::crypto::hash::sha512;

    // define some structures here
    #[derive(Copy, Clone)]
    pub struct PublicKey {
        g: G1,
        h: G1
    }

    #[derive(Copy, Clone)]
    pub struct Commitment {
        c: G1,
        d: Fr
    }

    impl fmt::Display for PublicKey {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let g_vec: Vec<u8> = encode(&self.g, Infinite).unwrap();
            let h_vec: Vec<u8> = encode(&self.h, Infinite).unwrap();
            let mut g_s = String::new();
            for x in g_vec.iter() {
                g_s = format!("{}{:x}", g_s, x);
            }

            let mut h_s = String::new();
            for y in h_vec.iter() {
                h_s = format!("{}{:x}", h_s, y);
            }

            write!(f, "PK : (g=0x{}, h=0x{})", g_s, h_s)
        }
    }


    impl fmt::Display for Commitment {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let c_vec: Vec<u8> = encode(&self.c, Infinite).unwrap();
            let mut c_s = String::new();
            for x in c_vec.iter() {
                c_s = format!("{}{:x}", c_s, x);
            }

            let d_vec: Vec<u8> = encode(&self.d, Infinite).unwrap();
            let mut d_s = String::new();
            for x in d_vec.iter() {
                d_s = format!("{}{:x}", d_s, x);
            }
            write!(f, "Commitment : (c=0x{}, d=0x{})", c_s, d_s)
        }
    }

    /*
    Implements the setup algorithm for the Pedersen92 commitment scheme
    */
    pub fn setup() -> PublicKey {
        println!("Run Setup...");
        let rng = &mut rand::thread_rng();
        let g = G1::random(rng);
        let h = G1::random(rng);
        let pk = PublicKey { g: g, h: h };
        println!("{}", pk);
        return pk;
    }

    #[derive(Copy, Clone)]
    pub struct Message {
    //    sk_sigs: SecretKeySigs, // the secret key for the signature scheme
        k1: Fr, // seed 1 for PRF
        k2: Fr, // seed 2 for PRF
        balance: i32 // the balance for the user
    }

    impl Message {
        pub fn new(_k1: Fr, _k2: Fr, _balance: i32) -> Message {
            Message {
                k1: _k1, k2: _k2, balance: _balance,
            }
        }

        fn hash(&self) -> Fr {
            let mut input_buf = Vec::new();
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


    /*
    commit(pk, msg) -> cm where
    - pk is the public key generated from setup()
    - msg is the message structure for the commitment scheme
    - cm is the output commitment message for the given message
    */
    pub fn commit(pk: &PublicKey, msg: &Message) -> Commitment {
        let rng = &mut rand::thread_rng();

        let r = Fr::random(rng);

        let m = msg.hash();
        let p = "commit -> m";
        debug_elem_in_hex(p, &m);

        let c = (pk.g * m) + (pk.h * r);
        // return (c, r) <- d=r
        let commitment = Commitment { c: c, d: r };

        // debugging
        println!("{}", commitment);
        return commitment;
    }

    /*
    decommit(pk, cm, msg) -> bool where
    - pk is the public key generated from setup()
    - cm is the commitment
    - msg is the message to validate
    - outputs T/F for whether the cm is a valid commitmentt to the msg
    */
    pub fn decommit(pk: &PublicKey, cm: &Commitment, msg: &Message) -> bool {
        let m = msg.hash();
        let p = "decommit -> m";
        debug_elem_in_hex(p, &m);

        let dm = (pk.g * m) + (pk.h * cm.d);
        return dm == cm.c;
    }

}
////////////////////////////////// COMMITMENT //////////////////////////////////

//pub fn keygen() {
//    println!("Run Keygen...");
//}
//
//pub fn init() {
//    println!("Run Init...");
//
//}
//
//pub fn refund() {
//    println!("Run Refund...");
//
//}
//
//pub fn refute() {
//    println!("Run Refute...");
//
//}
//
//pub fn resolve() {
//    println!("Run Resolve...");
//
//}
