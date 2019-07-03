extern crate rand;

use rand::{thread_rng, Rng};
use pairing::{Engine, CurveProjective};
use cl::{KeyPair, Signature, PublicParams, setup, BlindKeyPair, ProofState, SignatureProof, BlindPublicKey};
use ped92::{CSMultiParams, Commitment};
use ff::{Rand, Field, PrimeField};
use util::hash_g2_to_fr;

#[derive(Clone)]
struct Proof<E: Engine> {
    sigProof: SignatureProof<E>,
    T: E::G1,
    z: Vec<E::Fr>
}

fn prove<R: Rng, E: Engine>(rng: &mut R, com1: &Commitment<E>, com2: &Commitment<E>, oldWallet: Vec<E::Fr>, r: E::Fr,
                            newWallet: Vec<E::Fr>, rprime: E::Fr, paymentToken: &Signature<E>,
                            mpk: &PublicParams<E>, kp: &BlindKeyPair<E>) -> Proof<E> {
    let proofState = kp.prove_commitment(rng, &mpk, &paymentToken);
    let mut challenge = E::Fr::one();
    challenge.double();
    let sigProof = kp.prove_response(proofState, challenge, &mut vec! {hash_g2_to_fr::<E>(&com1.c)});

    Proof {sigProof, T: E::G1::rand(rng), z: vec!{}}
}

fn verify<E: Engine>(proof: Proof<E>, epsilon: E::Fr, com1: &Commitment<E>, com2: &Commitment<E>,
                     paymentToken: &Signature<E>, wpk: E::Fr, mpk: &PublicParams<E>, pk: &BlindPublicKey<E>) -> bool {
    let mut challenge = E::Fr::one();
    challenge.double();
    pk.verify_proof(&mpk, paymentToken.clone(), proof.sigProof, challenge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{Bls12, G1, G2, Fq12, Fr};

    #[test]
    #[ignore]
    fn nizk_proof_works() {
        let rng = &mut rand::thread_rng();
        let pkc = Fr::rand(rng);
        let wpk = Fr::rand(rng);
        let wpkprime = Fr::rand(rng);
        let bc = Fr::rand(rng);
        let mut bc2 = bc.clone();
        let bm = Fr::rand(rng);
        let mut bm2 = bm.clone();
        let epsilon = &Fr::rand(rng);
        bc2.sub_assign(epsilon);
        bm2.add_assign(epsilon);
        let r = Fr::rand(rng);
        let rprime = Fr::rand(rng);

        let com_params = CSMultiParams::<Bls12>::setup_gen_params(rng, 4);
        let wallet1 = vec! {pkc, wpk, bc, bm};
        let commitment1 = com_params.commit(rng, &wallet1, &r);
        let wallet2 = vec! {pkc, wpkprime, bc2, bm2};
        let commitment2 = com_params.commit(rng, &wallet2, &rprime);
        let mpk = setup(rng);
        let keypair = BlindKeyPair::<Bls12>::generate( rng, &mpk, 1);
        let payment_token = keypair.sign(rng, &vec! {hash_g2_to_fr::<Bls12>(&commitment1.c)});

        let proof = prove(rng, &commitment1, &commitment2, wallet1, r, wallet2, rprime, &payment_token, &mpk, &keypair);

        assert_eq!(verify(proof, *epsilon, &commitment1, &commitment2, &payment_token, wpk, &mpk, &keypair.public), true);
    }
}