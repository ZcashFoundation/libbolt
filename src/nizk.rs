extern crate pairing;
extern crate rand;

use super::*;
use rand::{thread_rng, Rng};
use cl::{KeyPair, Signature, PublicParams, setup, BlindKeyPair, ProofState, SignatureProof, BlindPublicKey};
use ped92::{CSParams, Commitment, CSMultiParams};
use pairing::{Engine, CurveProjective};
use ff::PrimeField;
use util::hash_g2_to_fr;
use commit_scheme::commit;

#[derive(Clone)]
struct Proof<E: Engine> {
    sig: Signature<E>,
    sigProof: SignatureProof<E>,
    T: E::G2,
    z: Vec<E::Fr>,
}

fn prove<R: Rng, E: Engine>(rng: &mut R, comParams: &CSMultiParams<E>, com1: &Commitment<E>, com2: &Commitment<E>, oldWallet: Vec<E::Fr>, r: E::Fr,
                            newWallet: Vec<E::Fr>, rPrime: E::Fr, paymentToken: &Signature<E>,
                            mpk: &PublicParams<E>, kp: &BlindKeyPair<E>) -> Proof<E> {
    let mut T = comParams.pub_bases[2].clone();
    let t1 = E::Fr::rand(rng);
    T.mul_assign(t1);
    let mut h = comParams.pub_bases[0].clone();
    let t2 = E::Fr::rand(rng);
    h.mul_assign(t2);
    T.add_assign(&h);
    let proofState = kp.prove_commitment(rng, &mpk, &paymentToken);
    let challenge = hash::<E>(proofState.a, T);
    let sigProof = kp.prove_response(&proofState, challenge, &mut vec! {hash_g2_to_fr::<E>(&com1.c)});

    let mut z1 = newWallet[2].clone();
    z1.negate();
    z1.mul_assign(&challenge);
    z1.add_assign(&t1);
    let mut z2 = r.clone();
    z2.sub_assign(&rPrime.clone());
    z2.mul_assign(&challenge);
    z2.add_assign(&t2);
    Proof { sig: proofState.blindSig, sigProof, T, z: vec! {z1, z2} }
}

fn verify<E: Engine>(proof: Proof<E>, epsilon: E::Fr, com1: &Commitment<E>, com2: &Commitment<E>,
                     paymentToken: &Signature<E>, wpk: E::Fr, comParams: &CSMultiParams<E>, mpk: &PublicParams<E>, pk: &BlindPublicKey<E>) -> bool {
    let challenge = hash::<E>(proof.sigProof.a, proof.T);

    let mut gWpk = comParams.pub_bases[2].clone();
    let mut minWpk = wpk.clone();
    minWpk.negate();
    gWpk.mul_assign(minWpk.into_repr());
    let mut gEps = comParams.pub_bases[4].clone();
    gEps.mul_assign(epsilon.into_repr());
    let mut gMinEps = comParams.pub_bases[3].clone();
    let mut mineps = epsilon.clone();
    mineps.negate();
    gMinEps.mul_assign(mineps.into_repr());

    let mut commitment = com1.c.clone();
    commitment.sub_assign(&com2.c.clone());
    commitment.add_assign(&gWpk);
    commitment.add_assign(&gEps);
    commitment.add_assign(&gMinEps);
    commitment.mul_assign(challenge.into_repr());
    commitment.add_assign(&proof.T);

    let mut g2 = comParams.pub_bases[2].clone();
    g2.mul_assign(proof.z[0].into_repr());
    let mut h = comParams.pub_bases[0].clone();
    h.mul_assign(proof.z[1].into_repr());
    g2.add_assign(&h);


    let r = pk.verify_proof(&mpk, proof.sig, proof.sigProof, challenge);

    r && commitment == g2
}

fn hash<E: Engine>(a: E::Fqk, T: E::G2) -> E::Fr {
    let mut x_vec: Vec<u8> = Vec::new();
    x_vec.extend(format!("{}", a).bytes());
    x_vec.extend(format!("{}", T).bytes());

    util::hash_to_fr::<E>(x_vec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{Bls12, G1, G2, Fq12, Fr};

    #[test]
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

        let comParams = CSMultiParams::<Bls12>::setup_gen_params(rng, 5);
        let wallet1 = vec! {r, pkc, wpk, bc, bm};
        let commitment1 = comParams.commit(rng, &wallet1, &r);
        let wallet2 = vec! {rprime, pkc, wpkprime, bc2, bm2};
        let commitment2 = comParams.commit(rng, &wallet2, &rprime);
        let mpk = setup(rng);
        let keypair = BlindKeyPair::<Bls12>::generate(rng, &mpk, 1);
        let payment_token = keypair.sign(rng, &vec! {hash_g2_to_fr::<Bls12>(&commitment1.c)});

        let proof = prove(rng, &comParams, &commitment1, &commitment2, wallet1, r, wallet2, rprime, &payment_token, &mpk, &keypair);

        assert_eq!(verify(proof, *epsilon, &commitment1, &commitment2, &payment_token, wpk, &comParams, &mpk, &keypair.public), true);
    }
}