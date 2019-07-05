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
    D: E::G2,
    z: Vec<E::Fr>,
}

fn prove<R: Rng, E: Engine>(rng: &mut R, comParams: &CSMultiParams<E>, com1: &Commitment<E>, r: E::Fr,
                            newWallet: Vec<E::Fr>, rPrime: E::Fr, paymentToken: &Signature<E>,
                            mpk: &PublicParams<E>, kp: &BlindKeyPair<E>) -> Proof<E> {
    //Commitment phase
    //Commit linear relationship
    let mut T = comParams.pub_bases[2].clone();
    let t1 = E::Fr::rand(rng);
    T.mul_assign(t1);
    let mut h = comParams.pub_bases[0].clone();
    let t2 = E::Fr::rand(rng);
    h.mul_assign(t2);
    T.add_assign(&h);

    //commit signature
    let proofState = kp.prove_commitment(rng, &mpk, &paymentToken);

    //commit commitment
    let mut D = E::G2::zero();
    let mut t = Vec::<E::Fr>::with_capacity(comParams.pub_bases.len() - 1);
    for g in comParams.pub_bases.clone() {
        let ti = E::Fr::rand(rng);
        t.push(ti);
        let mut gt = g.clone();
        gt.mul_assign(ti.into_repr());
        D.add_assign(&gt);
    }

    //Compute challenge
    let challenge = hash::<E>(proofState.a, T, D);

    //Response phase
    //response for signature
    let sigProof = kp.prove_response(&proofState, challenge, &mut vec! {hash_g2_to_fr::<E>(&com1.c)});

    //response linear relationship
    let mut z = Vec::<E::Fr>::with_capacity(t.len() + 2);
    let mut z1 = newWallet[1].clone();
    z1.negate();
    z1.mul_assign(&challenge);
    z1.add_assign(&t1);
    z.push(z1);
    let mut z2 = r.clone();
    z2.sub_assign(&rPrime.clone());
    z2.mul_assign(&challenge);
    z2.add_assign(&t2);
    z.push(z2);

    //response commitment
    let mut z0 = rPrime.clone();
    z0.mul_assign(&challenge);
    z0.add_assign(&t[0]);
    z.push(z0);
    for i in 1..t.len() {
        let mut zi = newWallet[i-1].clone();
        zi.mul_assign(&challenge);
        zi.add_assign(&t[i]);
        z.push(zi);
    }

    Proof { sig: proofState.blindSig, sigProof, T, D, z }
}

fn verify<E: Engine>(proof: Proof<E>, epsilon: E::Fr, com1: &Commitment<E>, com2: &Commitment<E>,
                     wpk: E::Fr, comParams: &CSMultiParams<E>, mpk: &PublicParams<E>, pk: &BlindPublicKey<E>) -> bool {
    //compute challenge
    let challenge = hash::<E>(proof.sigProof.a, proof.T, proof.D);

    //verify linear relationship
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
    let r = commitment == g2;

    //verify knowledge of signature
    let r1 = pk.verify_proof(&mpk, proof.sig, proof.sigProof, challenge);

    //verify knowledge of commitment
    let mut comc = com2.c.clone();
    comc.mul_assign(challenge.into_repr());
    comc.add_assign(&proof.D.clone());
    let mut x = E::G2::zero();
    for i in 2..proof.z.len() {
        let mut base = comParams.pub_bases[i - 2].clone();
        base.mul_assign(proof.z[i].into_repr());
        x.add_assign(&base);
    }
    let r3 = x == comc;

    r && r1 && r3
}

fn hash<E: Engine>(a: E::Fqk, T: E::G2, D: E::G2) -> E::Fr {
    let mut x_vec: Vec<u8> = Vec::new();
    x_vec.extend(format!("{}", a).bytes());
    x_vec.extend(format!("{}", T).bytes());
    x_vec.extend(format!("{}", D).bytes());

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

        let comParams = CSMultiParams::<Bls12>::setup_gen_params(rng, 4);
        let wallet1 = vec! {pkc, wpk, bc, bm};
        let commitment1 = comParams.commit(&wallet1, &r);
        let wallet2 = vec! {pkc, wpkprime, bc2, bm2};
        let commitment2 = comParams.commit(&wallet2, &rprime);
        let mpk = setup(rng);
        let keypair = BlindKeyPair::<Bls12>::generate(rng, &mpk, 1);
        let payment_token = keypair.sign(rng, &vec! {hash_g2_to_fr::<Bls12>(&commitment1.c)});

        let proof = prove(rng, &comParams, &commitment1, r, wallet2, rprime, &payment_token, &mpk, &keypair);

        assert_eq!(verify(proof, *epsilon, &commitment1, &commitment2, wpk, &comParams, &mpk, &keypair.public), true);
    }

    #[test]
    fn nizk_proof_false_statements() {
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

        let comParams = CSMultiParams::<Bls12>::setup_gen_params(rng, 4);
        let wallet1 = vec! {pkc, wpk, bc, bm};
        let wallet2 = vec! {pkc, wpkprime, bc2, bm2};
        let mpk = setup(rng);
        let keypair = BlindKeyPair::<Bls12>::generate(rng, &mpk, 1);

        let mut bc2Prime = bc.clone();
        let wallet3 = vec! {pkc, wpkprime, bc2Prime, bm2};
        let commitment1 = comParams.commit(&wallet1, &r);
        let commitment2 = comParams.commit(&wallet3, &rprime);
        let payment_token = keypair.sign(rng, &vec! {hash_g2_to_fr::<Bls12>(&commitment1.c)});
        let proof = prove(rng, &comParams, &commitment1, r, wallet3, rprime, &payment_token, &mpk, &keypair);
        assert_eq!(verify(proof, *epsilon, &commitment1, &commitment2, wpk, &comParams, &mpk, &keypair.public), false);

        let mut bm2Prime = bm.clone();
        let wallet4 = vec! {pkc, wpkprime, bc2, bm2Prime};
        let commitment1 = comParams.commit(&wallet1, &r);
        let commitment2 = comParams.commit(&wallet4, &rprime);
        let payment_token = keypair.sign(rng, &vec! {hash_g2_to_fr::<Bls12>(&commitment1.c)});
        let proof = prove(rng, &comParams, &commitment1, r, wallet4, rprime, &payment_token, &mpk, &keypair);
        assert_eq!(verify(proof, *epsilon, &commitment1, &commitment2, wpk, &comParams, &mpk, &keypair.public), false);

        let wallet5 = vec! {Fr::rand(rng), wpkprime, bc2, bm2};
        let commitment1 = comParams.commit(&wallet1, &r);
        let commitment2 = comParams.commit(&wallet5, &rprime);
        let payment_token = keypair.sign(rng, &vec! {hash_g2_to_fr::<Bls12>(&commitment1.c)});
        let proof = prove(rng, &comParams, &commitment1, r, wallet5, rprime, &payment_token, &mpk, &keypair);
        assert_eq!(verify(proof, *epsilon, &commitment1, &commitment2, wpk, &comParams, &mpk, &keypair.public), false);

    }
}