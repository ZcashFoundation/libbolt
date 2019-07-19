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
use wallet::Wallet;
use ccs08::{RPPublicParams, RangeProof};

#[derive(Clone)]
struct Proof<E: Engine> {
    pub sig: Signature<E>,
    pub sigProof: SignatureProof<E>,
    pub T: E::G1,
    pub D: E::G1,
    pub z: Vec<E::Fr>,
    pub rpParamsBC: RPPublicParams<E>,
    pub rpBC: RangeProof<E>,
    pub rpParamsBM: RPPublicParams<E>,
    pub rpBM: RangeProof<E>,
}

fn prove<R: Rng, E: Engine>(rng: &mut R, comParams: &CSMultiParams<E>, r: E::Fr,
                            oldWallet: Wallet<E>, newWallet: Wallet<E>, newWalletCom: Commitment<E>, rPrime: E::Fr, paymentToken: &Signature<E>,
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
    let mut D = E::G1::zero();
    let mut t = Vec::<E::Fr>::with_capacity(comParams.pub_bases.len() - 1);
    for g in comParams.pub_bases.clone() {
        let ti = E::Fr::rand(rng);
        t.push(ti);
        let mut gt = g.clone();
        gt.mul_assign(ti.into_repr());
        D.add_assign(&gt);
    }

    //commit range proof
    let rpParamsBC = RPPublicParams::setup(rng, 0, std::i32::MAX as i64, comParams.clone());
    let rpParamsBM = RPPublicParams::setup(rng, 0, std::i32::MAX as i64, comParams.clone());
    let rpStateBC = rpParamsBC.prove_commitment(rng, newWallet.bc.clone() as i64, newWalletCom.clone(), 3);
    let rpStateBM = rpParamsBM.prove_commitment(rng, newWallet.bm.clone() as i64, newWalletCom.clone(), 4);

    //Compute challenge
    //TODO: add commitment of range proofs
    let challenge = hash::<E>(proofState.a, vec!{T, D, rpStateBC.ps1.D, rpStateBC.ps2.D, rpStateBM.ps1.D, rpStateBM.ps2.D});

    //Response phase
    //response for signature
    let oldWalletVec = oldWallet.as_fr_vec();
    let sigProof = kp.prove_response(&proofState, challenge, &mut oldWalletVec.clone());

    //response linear relationship
    let mut z = Vec::<E::Fr>::with_capacity(t.len() + 2);
    let mut z1 = newWallet.wpk.clone();
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
    let newWalletVec = newWallet.as_fr_vec();
    for i in 1..t.len() {
        let mut zi = newWalletVec[i - 1].clone();
        zi.mul_assign(&challenge);
        zi.add_assign(&t[i]);
        z.push(zi);
    }

    //response range proof
    let rpBC = rpParamsBC.prove_response(rPrime.clone(), &rpStateBC, challenge.clone(), 3, vec!{newWalletVec[0], newWalletVec[1], newWalletVec[3]});
    let rpBM = rpParamsBM.prove_response(rPrime.clone(), &rpStateBM, challenge.clone(), 4, vec!{newWalletVec[0], newWalletVec[1], newWalletVec[2]});

    Proof { sig: proofState.blindSig, sigProof, T, D, z, rpParamsBC, rpBC, rpParamsBM, rpBM }
}

fn verify<E: Engine>(proof: Proof<E>, epsilon: E::Fr, com1: &Commitment<E>, com2: &Commitment<E>,
                     wpk: E::Fr, comParams: &CSMultiParams<E>, mpk: &PublicParams<E>, pk: &BlindPublicKey<E>) -> bool {
    //compute challenge
    let challenge = hash::<E>(proof.sigProof.a, vec!{proof.T, proof.D, proof.rpBC.p1.D, proof.rpBC.p2.D, proof.rpBM.p1.D, proof.rpBM.p2.D});

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
    let mut x = E::G1::zero();
    for i in 2..proof.z.len() {
        let mut base = comParams.pub_bases[i - 2].clone();
        base.mul_assign(proof.z[i].into_repr());
        x.add_assign(&base);
    }
    let r2 = x == comc;

    //verify range proofs
    let r3 = proof.rpParamsBC.verify(proof.rpBC, challenge.clone(), 3);
    let r4 = proof.rpParamsBM.verify(proof.rpBM, challenge.clone(), 4);

    r && r1 && r2 && r3 && r4
}

fn hash<E: Engine>(a: E::Fqk, T: Vec<E::G1>) -> E::Fr {
    let mut x_vec: Vec<u8> = Vec::new();
    x_vec.extend(format!("{}", a).bytes());
    for t in T {
        x_vec.extend(format!("{}", t).bytes());
    }

    util::hash_to_fr::<E>(x_vec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{Bls12, Fr};

    #[test]
    fn nizk_proof_works() {
        let rng = &mut rand::thread_rng();
        let pkc = Fr::rand(rng);
        let wpk = Fr::rand(rng);
        let wpkprime = Fr::rand(rng);
        let bc = rng.gen_range(100, 1000);
        let mut bc2 = bc.clone();
        let bm = rng.gen_range(100, 1000);
        let mut bm2 = bm.clone();
        let epsilon = &rng.gen_range(1, 100);
        bc2 -= epsilon;
        bm2 += epsilon;
        let r = Fr::rand(rng);
        let rprime = Fr::rand(rng);

        let mpk = setup(rng);
        let keypair = BlindKeyPair::<Bls12>::generate(rng, &mpk, 4);
        let comParams = keypair.generate_cs_multi_params(&mpk);
        let wallet1 = Wallet { pkc, wpk, bc, bm };
        let commitment1 = comParams.commit(&wallet1.as_fr_vec(), &r);
        let wallet2 = Wallet { pkc, wpk: wpkprime, bc: bc2, bm: bm2 };
        let commitment2 = comParams.commit(&wallet2.as_fr_vec(), &rprime);
        let blindPaymentToken = keypair.sign_blind(rng, &mpk, commitment1.clone());
        let paymentToken = keypair.unblind(&r, &blindPaymentToken);

        let proof = prove(rng, &comParams, r, wallet1, wallet2,
                          commitment2.clone(), rprime, &paymentToken, &mpk, &keypair);

        assert_eq!(verify(proof, Fr::from_str(&epsilon.to_string()).unwrap(), &commitment1,
                          &commitment2, wpk, &comParams, &mpk, &keypair.public), true);
    }

    #[test]
    fn nizk_proof_false_statements() {
        let rng = &mut rand::thread_rng();
        let pkc = Fr::rand(rng);
        let wpk = Fr::rand(rng);
        let wpkprime = Fr::rand(rng);
        let bc = rng.gen_range(100, 1000);
        let mut bc2 = bc.clone();
        let bm = rng.gen_range(100, 1000);
        let mut bm2 = bm.clone();
        let epsilon = &rng.gen_range(1, 100);
        bc2 -= epsilon;
        bm2 += epsilon;
        let r = Fr::rand(rng);
        let rprime = Fr::rand(rng);

        let mpk = setup(rng);
        let keypair = BlindKeyPair::<Bls12>::generate(rng, &mpk, 4);
        let comParams = keypair.generate_cs_multi_params(&mpk);
        let wallet1 = Wallet { pkc, wpk, bc, bm };
        let wallet2 = Wallet::<Bls12> { pkc, wpk: wpkprime, bc: bc2, bm: bm2 };

        let mut bc2Prime = bc.clone();
        let wallet3 = Wallet { pkc, wpk: wpkprime, bc: bc2Prime, bm: bm2 };
        let commitment1 = comParams.commit(&wallet1.as_fr_vec().clone(), &r);
        let commitment2 = comParams.commit(&wallet3.as_fr_vec(), &rprime);
        let blindPaymentToken = keypair.sign_blind(rng, &mpk, commitment1.clone());
        let paymentToken = keypair.unblind(&r, &blindPaymentToken);
        let proof = prove(rng, &comParams, r, wallet1.clone(), wallet3, commitment2.clone(), rprime, &paymentToken, &mpk, &keypair);
        assert_eq!(verify(proof, Fr::from_str(&epsilon.to_string()).unwrap(), &commitment1, &commitment2, wpk, &comParams, &mpk, &keypair.public), false);

        let mut bm2Prime = bm.clone();
        let wallet4 = Wallet { pkc, wpk: wpkprime, bc: bc2, bm: bm2Prime };
        let commitment2 = comParams.commit(&wallet4.as_fr_vec(), &rprime);
        let proof = prove(rng, &comParams, r, wallet1.clone(), wallet4, commitment2.clone(), rprime, &paymentToken, &mpk, &keypair);
        assert_eq!(verify(proof, Fr::from_str(&epsilon.to_string()).unwrap(), &commitment1, &commitment2, wpk, &comParams, &mpk, &keypair.public), false);

        let wallet5 = Wallet { pkc: Fr::rand(rng), wpk: wpkprime, bc: bc2, bm: bm2 };
        let commitment2 = comParams.commit(&wallet5.as_fr_vec(), &rprime);
        let proof = prove(rng, &comParams, r, wallet1.clone(), wallet5, commitment2.clone(), rprime, &paymentToken, &mpk, &keypair);
        assert_eq!(verify(proof, Fr::from_str(&epsilon.to_string()).unwrap(), &commitment1, &commitment2, wpk, &comParams, &mpk, &keypair.public), false);
    }
}