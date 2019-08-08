extern crate pairing;
extern crate rand;

use super::*;
use rand::{thread_rng, Rng};
use cl::{KeyPair, Signature, PublicParams, setup, BlindKeyPair, ProofState, SignatureProof, BlindPublicKey};
use ped92::{CSParams, Commitment, CSMultiParams};
use pairing::{Engine, CurveProjective};
use ff::PrimeField;
use commit_scheme::commit;
use wallet::Wallet;
use ccs08::{RPPublicParams, RangeProof};
use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
<E as pairing::Engine>::G1: serde::Serialize, \
<E as pairing::Engine>::G2: serde::Serialize, \
<E as pairing::Engine>::Fqk: serde::Serialize"
))]
#[serde(bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
<E as pairing::Engine>::G1: serde::Deserialize<'de>, \
<E as pairing::Engine>::G2: serde::Deserialize<'de>, \
<E as pairing::Engine>::Fqk: serde::Deserialize<'de>"
))]
pub struct Proof<E: Engine> {
    pub sig: Signature<E>,
    pub sigProof: SignatureProof<E>,
    pub D: E::G1,
    pub z: Vec<E::Fr>,
    pub rpBC: RangeProof<E>,
    pub rpBM: RangeProof<E>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
<E as pairing::Engine>::G1: serde::Serialize, \
<E as pairing::Engine>::G2: serde::Serialize"
))]
#[serde(bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
<E as pairing::Engine>::G1: serde::Deserialize<'de>, \
<E as pairing::Engine>::G2: serde::Deserialize<'de>"
))]
pub struct NIZKPublicParams<E: Engine> {
    pub mpk: PublicParams<E>,
    pub keypair: BlindKeyPair<E>,
    pub comParams: CSMultiParams<E>,
    pub rpParamsBC: RPPublicParams<E>,
    pub rpParamsBM: RPPublicParams<E>,
}

impl<E: Engine> NIZKPublicParams<E> {
    pub fn setup<R: Rng>(rng: &mut R, messageLength: usize) -> Self {
        let mpk = setup(rng);
        let keypair = BlindKeyPair::<E>::generate(rng, &mpk, messageLength);
        let comParams = keypair.generate_cs_multi_params(&mpk);
        let rpParamsBC = RPPublicParams::setup(rng, 0, std::i16::MAX as i32, comParams.clone());
        let rpParamsBM = RPPublicParams::setup(rng, 0, std::i16::MAX as i32, comParams.clone());

        NIZKPublicParams{mpk, keypair, comParams, rpParamsBC, rpParamsBM}
    }

    pub fn prove<R: Rng>(&self, rng: &mut R, r: E::Fr, oldWallet: Wallet<E>, newWallet: Wallet<E>,
                         newWalletCom: Commitment<E>, rPrime: E::Fr, paymentToken: &Signature<E>) -> Proof<E> {
        //Commitment phase
        //commit commitment
        let mut D = E::G1::zero();
        let w_len = newWallet.as_fr_vec().len();
        let diff = self.comParams.pub_bases.len() - w_len;
        let max = match (diff > 1) {
            true => w_len,
            false => self.comParams.pub_bases.len()
        };

        let mut t = Vec::<E::Fr>::with_capacity(max );
        for i in 0 .. max  {
            let ti = E::Fr::rand(rng);
            t.push(ti);
            let mut gt = self.comParams.pub_bases[i].clone();
            gt.mul_assign(ti.into_repr());
            D.add_assign(&gt);
        }

        //commit signature
        let fr1 = E::Fr::rand(rng);
        let tOptional = match (max > 4) {
            true => Some(vec!(t[1], fr1, t[3].clone(), t[4].clone())),
            false => Some(vec!(t[1], fr1, t[3].clone()))
        };
        let proofState = self.keypair.prove_commitment(rng, &self.mpk, &paymentToken, tOptional, None);

        //commit range proof
        let rpStateBC = self.rpParamsBC.prove_commitment(rng, newWallet.bc.clone(), newWalletCom.clone(), 3, Some(t[1..].to_vec()), Some(t[0].clone()));
        let rpStateBM = self.rpParamsBM.prove_commitment(rng, newWallet.bm.clone(), newWalletCom.clone(), 4, Some(t[1..].to_vec()), Some(t[0].clone()));

        //Compute challenge
        let challenge = NIZKPublicParams::<E>::hash(proofState.a, vec! {D, rpStateBC.ps1.D, rpStateBC.ps2.D, rpStateBM.ps1.D, rpStateBM.ps2.D});

        //Response phase
        //response for signature
        let oldWalletVec = oldWallet.as_fr_vec();
        let sigProof = self.keypair.prove_response(&proofState, challenge, &mut oldWalletVec.clone());

        //response commitment
        let mut z = Vec::<E::Fr>::with_capacity(t.len());
        let mut z0 = rPrime.clone();
        z0.mul_assign(&challenge);
        z0.add_assign(&t[0]);
        z.push(z0);
        let newWalletVec = newWallet.as_fr_vec();
//        println!("z.len = {}, wallet len = {}", t.len(), newWalletVec.len());
//        println!("max => {}", max);
        for i in 1..t.len() {
            let mut zi = newWalletVec[i - 1].clone();
            zi.mul_assign(&challenge);
            zi.add_assign(&t[i]);
            z.push(zi);
        }

        //response range proof
        let mut vec01 = newWalletVec[0..2].to_vec();
        let mut vecWithout2 = vec01.clone();
        let mut vec3 = newWalletVec[3..].to_vec();
        vecWithout2.append(&mut vec3);
        let mut vec2 = newWalletVec[2].clone();
        vec01.push( vec2);
        if newWalletVec.len() > 4 {
            let mut vec4 = newWalletVec[4..].to_vec();
            vec01.append(&mut vec4);
        }
        let rpBC = self.rpParamsBC.prove_response(rPrime.clone(), &rpStateBC, challenge.clone(), 3, vecWithout2.to_vec());
        let rpBM = self.rpParamsBM.prove_response(rPrime.clone(), &rpStateBM, challenge.clone(), 4, vec01.to_vec());

        Proof { sig: proofState.blindSig, sigProof, D, z, rpBC, rpBM }
    }

    pub fn verify(&self, proof: Proof<E>, epsilon: E::Fr, com2: &Commitment<E>, wpk: E::Fr) -> bool {
        //compute challenge
        let challenge = NIZKPublicParams::<E>::hash(proof.sigProof.a, vec! {proof.D, proof.rpBC.p1.D, proof.rpBC.p2.D, proof.rpBM.p1.D, proof.rpBM.p2.D});

        //verify knowledge of signature
        let r1 = self.keypair.public.verify_proof(&self.mpk, proof.sig, proof.sigProof.clone(), challenge);

        //verify knowledge of commitment
        let mut comc = com2.c.clone();
        comc.mul_assign(challenge.into_repr());
        comc.add_assign(&proof.D.clone());
        let mut x = E::G1::zero();
        for i in 0..proof.z.len() {
            let mut base = self.comParams.pub_bases[i].clone();
            base.mul_assign(proof.z[i].into_repr());
            x.add_assign(&base);
        }
        let r2 = x == comc;

        //verify range proofs
        let r3 = self.rpParamsBC.verify(proof.rpBC.clone(), challenge.clone(), 3);
        let r4 = self.rpParamsBM.verify(proof.rpBM.clone(), challenge.clone(), 4);

        //verify linear relationship
        let mut r5 = proof.z[1] == proof.sigProof.zsig[0];
        let mut zsig2 = proof.sigProof.zsig[2].clone();
        let mut epsC = epsilon.clone();
        epsC.mul_assign(&challenge.clone());
        zsig2.sub_assign(&epsC.clone());
        r5 = r5 && proof.z[3] == zsig2;
        let mut zsig3 = proof.sigProof.zsig[3].clone();
        zsig3.add_assign(&epsC.clone());
        r5 = r5 && proof.z[4] == zsig3;

        r5 = r5 && proof.z[0] == proof.rpBC.p1.zr;
        r5 = r5 && proof.z[0] == proof.rpBC.p2.zr;
        r5 = r5 && proof.z[0] == proof.rpBM.p1.zr;
        r5 = r5 && proof.z[0] == proof.rpBM.p2.zr;
        for i in 1..proof.z.len() {
            if i == 3 {
                r5 = r5 && proof.z[i] == proof.rpBM.p1.zs[i-1];
                r5 = r5 && proof.z[i] == proof.rpBM.p2.zs[i-1].clone();
            } else if i >= 4 {
                r5 = r5 && proof.z[i] == proof.rpBC.p1.zs[i-2].clone();
                r5 = r5 && proof.z[i] == proof.rpBC.p2.zs[i-2].clone();
            } else {
                r5 = r5 && proof.z[i] == proof.rpBC.p1.zs[i-1].clone();
                r5 = r5 && proof.z[i] == proof.rpBC.p2.zs[i-1].clone();
                r5 = r5 && proof.z[i] == proof.rpBM.p1.zs[i-1].clone();
                r5 = r5 && proof.z[i] == proof.rpBM.p2.zs[i-1].clone();
            }
        }

        r1 && r2 && r3 && r4 && r5
    }

    fn hash(a: E::Fqk, T: Vec<E::G1>) -> E::Fr {
        let mut x_vec: Vec<u8> = Vec::new();
        x_vec.extend(format!("{}", a).bytes());
        for t in T {
            x_vec.extend(format!("{}", t).bytes());
        }

        util::hash_to_fr::<E>(x_vec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{Bls12, Fr};
    use util::convert_int_to_fr;

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

        let pubParams = NIZKPublicParams::<Bls12>::setup(rng, 4);
        let wallet1 = Wallet { pkc, wpk, bc, bm, close: None };
        let commitment1 = pubParams.comParams.commit(&wallet1.as_fr_vec(), &r);
        let wallet2 = Wallet { pkc, wpk: wpkprime, bc: bc2, bm: bm2, close: None };
        let commitment2 = pubParams.comParams.commit(&wallet2.as_fr_vec(), &rprime);
        let blindPaymentToken = pubParams.keypair.sign_blind(rng, &pubParams.mpk, commitment1.clone());
        let paymentToken = pubParams.keypair.unblind(&r, &blindPaymentToken);

        let proof = pubParams.prove(rng, r, wallet1, wallet2,
                          commitment2.clone(), rprime, &paymentToken);
        let fr = convert_int_to_fr::<Bls12>(*epsilon);
        assert_eq!(pubParams.verify(proof, fr, &commitment2, wpk), true);
    }

    #[test]
    fn nizk_proof_negative_value_works() {
        let rng = &mut rand::thread_rng();
        let pkc = Fr::rand(rng);
        let wpk = Fr::rand(rng);
        let wpkprime = Fr::rand(rng);
        let bc = rng.gen_range(100, 1000);
        let mut bc2 = bc.clone();
        let bm = rng.gen_range(100, 1000);
        let mut bm2 = bm.clone();
        let epsilon = &rng.gen_range(-100, -1);
        bc2 -= epsilon;
        bm2 += epsilon;
        let r = Fr::rand(rng);
        let rprime = Fr::rand(rng);

        let pubParams = NIZKPublicParams::<Bls12>::setup(rng, 4);
        let wallet1 = Wallet { pkc, wpk, bc, bm, close: None };
        let commitment1 = pubParams.comParams.commit(&wallet1.as_fr_vec(), &r);
        let wallet2 = Wallet { pkc, wpk: wpkprime, bc: bc2, bm: bm2, close: None };
        let commitment2 = pubParams.comParams.commit(&wallet2.as_fr_vec(), &rprime);
        let blindPaymentToken = pubParams.keypair.sign_blind(rng, &pubParams.mpk, commitment1.clone());
        let paymentToken = pubParams.keypair.unblind(&r, &blindPaymentToken);

        let proof = pubParams.prove(rng, r, wallet1, wallet2,
                                    commitment2.clone(), rprime, &paymentToken);
        let fr = convert_int_to_fr::<Bls12>(*epsilon);
        assert_eq!(pubParams.verify(proof, fr, &commitment2, wpk), true);
    }

    #[test]
    fn nizk_proof_close_works() {
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

        let _closeToken = Fr::rand(rng);
        let pubParams = NIZKPublicParams::<Bls12>::setup(rng, 5);
        let wallet1 = Wallet { pkc, wpk, bc, bm, close: None };
        let commitment1 = pubParams.comParams.commit(&wallet1.as_fr_vec(), &r);
        let wallet2 = Wallet { pkc, wpk: wpkprime, bc: bc2, bm: bm2, close: Some(_closeToken) };
        let commitment2 = pubParams.comParams.commit(&wallet2.as_fr_vec(), &rprime);
        let blindPaymentToken = pubParams.keypair.sign_blind(rng, &pubParams.mpk, commitment1.clone());
        let paymentToken = pubParams.keypair.unblind(&r, &blindPaymentToken);

        let blindCloseToken = pubParams.keypair.sign_blind(rng, &pubParams.mpk, commitment2.clone());
        let closeToken = pubParams.keypair.unblind(&rprime, &blindCloseToken);

        // verify the blind signatures
        let pk = pubParams.keypair.get_public_key(&pubParams.mpk);
        assert!(pk.verify(&pubParams.mpk, &wallet1.as_fr_vec(), &paymentToken));

        println!("close => {}", &wallet2);
        assert!(pk.verify(&pubParams.mpk, &wallet2.as_fr_vec(), &closeToken));

        let proof = pubParams.prove(rng, r, wallet1, wallet2,
                                    commitment2.clone(), rprime, &paymentToken);

        assert_eq!(pubParams.verify(proof, Fr::from_str(&epsilon.to_string()).unwrap(), &commitment2, wpk), true);
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

        let pubParams = NIZKPublicParams::<Bls12>::setup(rng, 4);
        let wallet1 = Wallet { pkc, wpk, bc, bm, close: None };
        let wallet2 = Wallet::<Bls12> { pkc, wpk: wpkprime, bc: bc2, bm: bm2, close: None };

        let bc2Prime = bc.clone();
        let wallet3 = Wallet { pkc, wpk: wpkprime, bc: bc2Prime, bm: bm2, close: None };
        let commitment1 = pubParams.comParams.commit(&wallet1.as_fr_vec().clone(), &r);
        let commitment2 = pubParams.comParams.commit(&wallet3.as_fr_vec(), &rprime);
        let blindPaymentToken = pubParams.keypair.sign_blind(rng, &pubParams.mpk, commitment1.clone());
        let paymentToken = pubParams.keypair.unblind(&r, &blindPaymentToken);
        let proof = pubParams.prove(rng, r, wallet1.clone(), wallet3, commitment2.clone(), rprime, &paymentToken);
        assert_eq!(pubParams.verify(proof, Fr::from_str(&epsilon.to_string()).unwrap(), &commitment2, wpk), false);

        let bm2Prime = bm.clone();
        let wallet4 = Wallet { pkc, wpk: wpkprime, bc: bc2, bm: bm2Prime, close: None };
        let commitment2 = pubParams.comParams.commit(&wallet4.as_fr_vec(), &rprime);
        let proof = pubParams.prove(rng, r, wallet1.clone(), wallet4, commitment2.clone(), rprime, &paymentToken);
        assert_eq!(pubParams.verify(proof, Fr::from_str(&epsilon.to_string()).unwrap(), &commitment2, wpk), false);

        let wallet5 = Wallet { pkc: Fr::rand(rng), wpk: wpkprime, bc: bc2, bm: bm2, close: None };
        let commitment2 = pubParams.comParams.commit(&wallet5.as_fr_vec(), &rprime);
        let proof = pubParams.prove(rng, r, wallet1.clone(), wallet5, commitment2.clone(), rprime, &paymentToken);
        assert_eq!(pubParams.verify(proof, Fr::from_str(&epsilon.to_string()).unwrap(), &commitment2, wpk), false);
    }

    #[test]
    fn test_nizk_serialization() {
        let mut rng = &mut rand::thread_rng();

        let l = 5;
        let mpk = setup(&mut rng);
        let blindkeypair = BlindKeyPair::<Bls12>::generate(&mut rng, &mpk, l);
        let comParams = blindkeypair.generate_cs_multi_params(&mpk);
        let rpParamsBC = ccs08::RPPublicParams::setup(rng, 0, std::i16::MAX as i32, comParams.clone());
        let rpParamsBM = ccs08::RPPublicParams::setup(rng, 0, std::i16::MAX as i32, comParams.clone());

        let nizk_params = NIZKPublicParams { mpk: mpk, keypair: blindkeypair, comParams: comParams, rpParamsBC: rpParamsBC, rpParamsBM: rpParamsBM };

        let is_serialized = serde_json::to_vec(&nizk_params).unwrap();
        println!("NIZK Struct len: {}", is_serialized.len());

        // deserialize
    }

}
