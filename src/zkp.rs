// -*- coding: utf-8; mode: rust; -*-
//
// To the extent possible under law, the authors have waived all
// copyright and related or neighboring rights to zkp,
// using the Creative Commons "CC0" public domain dedication.  See
// <http://creativecommons.org/publicdomain/zero/1.0/> for full
// details.
//
// Authors:
// - Henry de Valence <hdevalence@hdevalence.ca>

//! This crate has an experimental zero-knowledge proof compiler
//! implemented using Rust macros.
//!
//! It provides a DSL resembing Camenisch-Stadler notation for proving
//! statements about discrete logarithms in the Ristretto group on
//! BLS-381, as implemented in
//! [`bn module`](https://github.com/zcash-hackworks/bn).

#![allow(non_snake_case)]
#![feature(test)]

//extern crate serde;
//
//#[doc(hidden)]
//#[macro_use]
//pub extern crate serde_derive;
//#[doc(hidden)]
//pub extern crate bn;
//#[doc(hidden)]
//pub extern crate rand;

#[doc(hidden)]
#[macro_export]
macro_rules! __compute_formula_scalarlist {
    // Unbracket a statement
    (($publics:ident, $scalars:ident) ($($x:tt)*)) => {
        // Add a trailing +
        __compute_formula_scalarlist!(($publics,$scalars) $($x)* +)
    };
    // Inner part of the formula: give a list of &Scalars
    // Since there's a trailing +, we can just generate the list as normal...
    (($publics:ident, $scalars:ident)
     $( $point:ident * $scalar:ident +)+ ) => {
        &[ $( $scalars.$scalar ,)* ]
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __compute_formula_pointlist {
    // Unbracket a statement
    (($publics:ident, $scalars:ident) ($($x:tt)*)) => {
        // Add a trailing +
        __compute_formula_pointlist!(($publics,$scalars) $($x)* +)
    };
    // Inner part of the formula: give a list of &Scalars
    // Since there's a trailing +, we can just generate the list as normal...
    (($publics:ident, $scalars:ident)
     $( $point:ident * $scalar:ident +)* ) => {
        &[ $( *($publics.$point) ,)* ]
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __compute_commitments_consttime {
    (($publics:ident, $scalars:ident) $($lhs:ident = $statement:tt),+) => {
        Commitments {
            $( $lhs :
               multiscalar_mult(
                   __compute_formula_scalarlist!(($publics, $scalars) $statement),
                   __compute_formula_pointlist!(($publics, $scalars) $statement),
               )
            ),+
        }
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! __recompute_commitments_vartime {
    (($publics:ident, $scalars:ident, $minus_c:ident) $($lhs:ident = $statement:tt),+) => {
        Commitments {
            $( $lhs :
               vartime::multiscalar_mult(
                   __compute_formula_scalarlist!(($publics, $scalars) $statement)
                       .into_iter()
                       .chain(iter::once(&($minus_c)))
                   ,
                   __compute_formula_pointlist!(($publics, $scalars) $statement)
                       .into_iter()
                       .chain(iter::once($publics.$lhs))
               )
            ),+
        }
    }
}

/// Creates a module with code required to produce a non-interactive
/// zero-knowledge proof statement, to serialize it to wire format, to
/// parse from wire format, and to verify the proof statement.
///
/// The statement is specified in an embedded DSL resembling
/// Camenisch-Stadler notation.  For instance, a proof of knowledge of
/// two equal discrete logarithms ("DLEQ") is specified as:
///
/// ```rust,ignore
/// create_nipk!{dleq, (x), (A, B, G, H) : A = (G * x), B = (H * x) }
/// ```
///
/// This creates a module `dleq` with code for proving knowledge of a
/// secret `x: Scalar` such that `A = G*x`, `B = H*x` for public
/// parameters `A, B, G, H: G1`.  In general the syntax is
///
/// ```rust,ignore
/// create_nipk!{
///     module_name, // used to label proof statements
///     (x,y,z,...), // secret variable names
///     (A,B,C,...)  // public parameter names
///     :
///     LHS = (A * x + B * y + C * z + ... ),  // comma-seperated statements
///     ...
/// }
/// ```
///
/// Statements have the form `LHS = (A * x + B * y + C * z + ... )`,
/// where `LHS` is one of the points listed as a public parameter, and
/// the right-hand side is a sum of public points multiplied by secret
/// scalars.
///
/// Inside the generated module `module_name`, the macro defines three
/// structs:
///
/// A `Publics` struct corresponding to the public parameters, of the
/// form
///
/// ```rust,ignore
/// pub struct Publics<'a> { pub A: &'a G1, ... }
/// ```
///
/// A `Secrets` struct corresponding to the secret parameters, of the
/// form
///
/// ```rust,ignore
/// pub struct Secrets<'a> { pub x: &'a Scalar, ... }
/// ```
///
/// A `Proof` struct, of the form
///
/// ```rust,ignore
/// #[derive(Serialize, Deserialize)]
/// pub struct Proof { ... }
///
/// impl Proof {
///     pub fn create<R: Rng>(
///         rng: &mut R,
///         publics: Publics,
///         secrets: Secrets,
///     ) -> Proof { ... }
///
///     pub fn verify(&self, publics: Publics) -> Result<(),()> { ... }
/// }
/// ```
///
/// The `Proof` struct derives the Serde traits, so it can be
/// serialized and deserialized to various wire formats.
///
/// The `Publics` and `Secrets` structs are used to fake named
/// arguments in the input to `create` and `verify`.  Proof creation
/// is done in constant time.  Proof verification uses variable-time
/// code.
///
/// As an example, we can create and verify a DLEQ proof as follows:
///
/// ```
/// #[macro_use]
/// extern crate serde_derive;
///
/// #[macro_use]
/// extern crate zkp;
///
/// extern crate rand;
/// use rand;
///
/// extern crate bincode;
///
/// # fn main() {
/// let mut rng = OsRng::new().unwrap();
/// let G = &dalek_constants::RISTRETTO_BASEPOINT_POINT;
/// let H = RistrettoPoint::hash_from_bytes::<Sha256>(G.compress().as_bytes());
///
/// create_nipk!{dleq, (x), (A, B, G, H) : A = (G * x), B = (H * x) }
///
/// let x = Fr::from_str("89327492234");
/// let A =  G * &x;
/// let B = &H * &x;
///
/// let publics = dleq::Publics{A: &A, B: &B, G: G, H: &H};
/// let secrets = dleq::Secrets{x: &x};
///
/// let proof = dleq::Proof::create(&mut rng, publics, secrets);
///
/// // Serialize to bincode representation
/// let proof_bytes = bincode::serialize(&proof, bincode::Infinite).unwrap();
///
/// // Send bytes over the wire here ...
///
/// // Parse bytes back to in-memory representation
/// let parsed_proof: dleq::Proof
///     = bincode::deserialize(&proof_bytes).unwrap();
///
/// // Check the proof.
/// assert!(parsed_proof.verify(publics).is_ok());
/// # }
/// ```
#[macro_export]
macro_rules! create_nipk {
    (
        $proof_module_name:ident // Name of the module to create
        ,
        ( $($secret:ident),+ ) // Secret variables, sep by commas
        ,
        ( $($public:ident),+ ) // Public variables, sep by commas
        :
        // List of statements to prove
        // Format: LHS = ( ... RHS expr ... ),
        $($lhs:ident = $statement:tt),+
    ) => {
        mod $proof_module_name {
            use $crate::{Group, Fr, G1}
            use $crate::sodiumoxide::crypto::hash;
            // use $crate::sha2::{Digest, Sha512};
            use $crate::rand::Rng;

            use std::iter;

            #[derive(Copy, Clone)]
            pub struct Secrets<'a> {
                // Create a parameter for each secret value
                $(
                    pub $secret : &'a Fr,
                )+
            }

            #[derive(Copy, Clone)]
            pub struct Publics<'a> {
                // Create a parameter for each public value
                $(
                    pub $public : &'a G1,
                )+
            }

            // Hack because we can't concat identifiers,
            // so do responses.x instead of responses_x
            // rand.x instead of rand_x, etc.

            struct Commitments {$($lhs: G1,)+ }
            struct Randomnesses {$($secret : Scalar,)+}
            #[derive(Serialize, Deserialize)]
            struct Responses {$($secret : Scalar,)+}

            #[derive(Serialize, Deserialize)]
            pub struct Proof {
                challenge: Fr,
                responses: Responses,
            }

            impl Proof {
                /// Create a `Proof`, in constant time, from the given
                /// `Publics` and `Secrets`.
                #[allow(dead_code)]
                pub fn create<R: Rng>(
                    rng: &mut R,
                    publics: Publics,
                    secrets: Secrets,
                ) -> Proof {
                    let rand = Randomnesses{
                        $(
                            $secret : Fr::random(rng),
                        )+
                    };
                    // $statement_rhs = `X * x + Y * y + Z * z`
                    // should become
                    // `publics.X * rand.x + publics.Y * rand.y + publics.Z * rand.z`
                    let commitments: Commitments;
                    commitments = __compute_commitments_consttime!(
                        (publics, rand) $($lhs = $statement),*
                    );

                    let mut hash_state = hash::State::new();

                    $(
                        hash_state.update(publics.$public.as_bytes());
                    )+
                    $(
                        hash_state.update(commitments.$lhs.as_bytes());
                    )+

                    let digest = hash_state.finalize();
                    let mut digest_buf: [u8; 64] = [0; 64];
                    digest_buf.copy_from_slice(&digest[0..64]);
                    let challenge = Fr::interpret(&digest_buf); // Scalar::from_hash(hash);

                    let responses = Responses{
                        $(
                            $secret : &(&challenge * secrets.$secret) + &rand.$secret,
                        )+
                    };

                    Proof{ challenge: challenge, responses: responses }
                }

                /// Verify the `Proof` using the public parameters `Publics`.
                #[allow(dead_code)]
                pub fn verify(&self, publics: Publics) -> Result<(),()> {
                    // `A = X * x + Y * y`
                    // should become
                    // `publics.X * responses.x + publics.Y * responses.y - publics.A * self.challenge`
                    let responses = &self.responses;
                    let minus_c = -&self.challenge;
                    let commitments = __recompute_commitments_vartime!(
                        (publics, responses, minus_c) $($lhs = $statement),*
                    );

                    let mut hash_state = hash::State::new();
                    // Add each public point into the hash
                    $(
                        hash_state.update(publics.$public.as_bytes());
                    )+
                    // Add each (recomputed) commitment into the hash
                    $(
                        hash_state.update(commitments.$lhs.as_bytes());
                    )*

                    let digest = hash_state.finalize();
                    let mut digest_buf: [u8; 64] = [0; 64];
                    digest_buf.copy_from_slice(&digest[0..64]);
                    // Recompute challenge
                    let challenge = Fr::interpret(&digest_buf); // Scalar::from_hash(hash);

                    if challenge == self.challenge { Ok(()) } else { Err(()) }
                }
            }

            #[cfg(test)]
            mod bench {
                extern crate test;

                use $crate::rand;

                use super::*;

                use self::test::Bencher;

                #[bench]
                #[allow(dead_code)]
                fn create(b: &mut Bencher) {
                    let rng = &mut rand::thread_rng();                
                    //let mut rng = OsRng::new().unwrap();

                    // Need somewhere to actually put the public points
                    struct DummyPublics { $( pub $public : G1, )+ }
                    let dummy_publics = DummyPublics {
                        $( $public : G1::random(&mut rng) , )+
                    };

                    let publics = Publics {
                        $( $public : &dummy_publics.$public , )+
                    };

                    struct DummySecrets { $( pub $secret : Fr, )+ }
                    let dummy_secrets = DummySecrets {
                        $( $secret : Fr::random(&mut rng) , )+
                    };

                    let secrets = Secrets {
                        $( $secret : &dummy_secrets.$secret , )+
                    };

                    b.iter(|| Proof::create(&mut rng, publics, secrets));
                }

                #[bench]
                #[allow(dead_code)]
                fn verify(b: &mut Bencher) {
                    let mut rng = OsRng::new().unwrap();

                    // Need somewhere to actually put the public points
                    struct DummyPublics { $( pub $public : G1, )+ }
                    let dummy_publics = DummyPublics {
                        $( $public : G1::random(&mut rng) , )+
                    };

                    let publics = Publics {
                        $( $public : &dummy_publics.$public , )+
                    };

                    struct DummySecrets { $( pub $secret : Fr, )+ }
                    let dummy_secrets = DummySecrets {
                        $( $secret : Fr::random(&mut rng) , )+
                    };

                    let secrets = Secrets {
                        $( $secret : &dummy_secrets.$secret , )+
                    };

                    let p = Proof::create(&mut rng, publics, secrets);

                    b.iter(|| p.verify(publics));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate bincode;
    extern crate test;

    use rand;
    use bn::{Group, Fr, G1};
//    use self::test::Bencher;

//    use curve25519_dalek::constants as dalek_constants;
//    use curve25519_dalek::ristretto::RistrettoPoint;
//    use curve25519_dalek::scalar::Scalar;

    #[test]
    fn create_gen_dleq(b: &mut Bencher) {
        let rng = &mut rand::thread_rng();
        let G = G1::random(rng); // &dalek_constants::RISTRETTO_BASEPOINT_POINT;
        let H = G1::random(rng); // RistrettoPoint::hash_from_bytes::<Sha256>(G.compress().as_bytes());

        create_nipk!{dleq, (x), (A, B, G, H) : A = (G * x), B = (H * x) }

        let x = Fr::from_str("89327492234").unwrap();
        let A =  G * x;
        let B = H * x;

        let publics = dleq::Publics{A: &A, B: &B, G: G, H: &H};
        let secrets = dleq::Secrets{x: &x};

        let proof = dleq::Proof::create(&mut rng, publics, secrets);
        // serialize to bincode representation
        let proof_bytes = bincode::serialize(&proof, bincode::Infinite).unwrap();
        // parse bytes back to memory
        let parsed_proof: dleq::Proof
            = bincode::deserialize(&proof_bytes).unwrap();

        assert!(parsed_proof.verify(publics).is_ok());

//        b.iter(|| dleq::Proof::create(&mut rng, publics, secrets));
    }

//    #[bench]
//    fn verify_gen_dleq(b: &mut Bencher) {
//        let mut rng = OsRng::new().unwrap();
//        let G = &dalek_constants::RISTRETTO_BASEPOINT_POINT;
//        let H = RistrettoPoint::hash_from_bytes::<Sha256>(G.compress().as_bytes());
//
//        create_nipk!{dleq, (x), (A, B, G, H) : A = (G * x), B = (H * x) }
//
//        let x = Scalar::from_u64(89327492234);
//        let A =  G * &x;
//        let B = &H * &x;
//
//        let publics = dleq::Publics{A: &A, B: &B, G: G, H: &H};
//        let secrets = dleq::Secrets{x: &x};
//
//        let proof = dleq::Proof::create(&mut rng, publics, secrets);
//        b.iter(|| proof.verify(publics).is_ok());
//    }
//
//    #[test]
//    fn create_and_verify_gen_dleq() {
//        let mut rng = OsRng::new().unwrap();
//        let G = &dalek_constants::RISTRETTO_BASEPOINT_POINT;
//        let H = RistrettoPoint::hash_from_bytes::<Sha256>(G.compress().as_bytes());
//
//        create_nipk!{dleq, (x), (A, B, G, H) : A = (G * x), B = (H * x) }
//
//        let x = Scalar::from_u64(89327492234);
//        let A =  G * &x;
//        let B = &H * &x;
//
//        let publics = dleq::Publics{A: &A, B: &B, G: G, H: &H};
//        let secrets = dleq::Secrets{x: &x};
//
//        let proof = dleq::Proof::create(&mut rng, publics, secrets);
//        // serialize to bincode representation
//        let proof_bytes = bincode::serialize(&proof, bincode::Infinite).unwrap();
//        // parse bytes back to memory
//        let parsed_proof: dleq::Proof
//            = bincode::deserialize(&proof_bytes).unwrap();
//
//        assert!(parsed_proof.verify(publics).is_ok());
//    }
}