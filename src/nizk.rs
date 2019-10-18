extern crate pairing;
extern crate rand;

use super::*;
use rand::Rng;
use cl::{Signature, PublicParams, setup, BlindKeyPair, SignatureProof, BlindPublicKey};
use ped92::{Commitment, CSMultiParams, CommitmentProof};
use pairing::{Engine, CurveProjective};
use wallet::Wallet;
use ccs08::{SecretParamsUL, ParamsUL, ProofUL};
use serde::{Serialize, Deserialize};
use util;

/// NIZKProof is the object that represents the NIZK Proof of Knowledge during the payment and closing protocol
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
pub struct NIZKProof<E: Engine> {
    pub sig: Signature<E>,
    pub sigProof: SignatureProof<E>,
    pub comProof: CommitmentProof<E>,
    pub rpBC: ProofUL<E>,
    pub rpBM: ProofUL<E>,
}

/// NIZKPublicParams are public parameters to perform a NIZK Proof of Knowledge during the payment and closing protocol
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
    pub pk: BlindPublicKey<E>,
    pub comParams: CSMultiParams<E>,
    pub rpParams: ParamsUL<E>,
}

/// NIZKSecretParams are secret parameters to perform the verification of a NIZK Proof of Knowledge during the payment and closing protocol
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
<E as pairing::Engine>::G1: serde::Serialize, \
<E as pairing::Engine>::G2: serde::Serialize"
))]
#[serde(bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
<E as pairing::Engine>::G1: serde::Deserialize<'de>, \
<E as pairing::Engine>::G2: serde::Deserialize<'de>"
))]
pub struct NIZKSecretParams<E: Engine> {
    pub pubParams: NIZKPublicParams<E>,
    pub keypair: BlindKeyPair<E>,
    pub rpParams: SecretParamsUL<E>,
}

impl<E: Engine> NIZKSecretParams<E> {
    /// Basic setup for the NIZKPublicParams
    /// Takes as input a random generator and the length of the message which should be 4 during payment protocol and 5 for the closing protocol
    pub fn setup<R: Rng>(rng: &mut R, messageLength: usize) -> Self {
        let mpk = setup(rng);
        let keypair = BlindKeyPair::<E>::generate(rng, &mpk, messageLength);
        let comParams = keypair.generate_cs_multi_params(&mpk);
        let u = 128; //TODO: make u and l configurable
        let l = 9;
        let rpParams = SecretParamsUL::setup_ul(rng, u, l, comParams.clone());
        let pubParams = NIZKPublicParams { mpk, pk: keypair.public.clone(), comParams, rpParams: rpParams.pubParams.clone() };

        NIZKSecretParams { pubParams, keypair, rpParams }
    }

    /**
        Verify a NIZK Proof of Knowledge during payment or closing protocol
        Input:
        proof: A NIZK proof created by the Customer
        epsilon: The transaction amount of the payment
        com: Commitment of the new wallet that needs to be signed
        wpk: reveal of wallet public key of the old wallet.
    */
    pub fn verify(&self, proof: NIZKProof<E>, epsilon: E::Fr, com: &Commitment<E>, wpk: E::Fr) -> bool {
        //verify signature is not the identity
        let r0 = proof.sig.h != E::G1::one();

        //compute challenge
        let challenge = NIZKPublicParams::<E>::hash(proof.sigProof.a, vec! {proof.comProof.T, proof.rpBC.D, proof.rpBM.D});

        //verify knowledge of signature
        let mut r1 = self.keypair.public.verify_proof(&self.pubParams.mpk, proof.sig, proof.sigProof.clone(), challenge);
        let mut wpkc = wpk.clone();
        wpkc.mul_assign(&challenge.clone());
        r1 = r1 && proof.sigProof.zsig[1] == wpkc;

        //verify knowledge of commitment
        let r2 = proof.comProof.verify_proof(&self.pubParams.comParams, &com.c.clone(), &challenge, None);

        //verify range proofs
        let r3 = self.rpParams.verify_ul(&proof.rpBC.clone(), challenge.clone(), 3);
        let r4 = self.rpParams.verify_ul(&proof.rpBM.clone(), challenge.clone(), 4);

        //verify linear relationship
        let mut r5 = proof.comProof.z[1] == proof.sigProof.zsig[0];
        let mut zsig2 = proof.sigProof.zsig[2].clone();
        let mut epsC = epsilon.clone();
        epsC.mul_assign(&challenge.clone());
        zsig2.sub_assign(&epsC.clone());
        r5 = r5 && proof.comProof.z[3] == zsig2;
        let mut zsig3 = proof.sigProof.zsig[3].clone();
        zsig3.add_assign(&epsC.clone());
        r5 = r5 && proof.comProof.z[4] == zsig3;

        r0 && r1 && r2 && r3 && r4 && r5
    }
}

impl<E: Engine> NIZKPublicParams<E> {
    /** This method can be called to create the proof during the payment and closing protocol
        Input:
        rng: random generator
        oldWallet: This is the wallet before payment occurs
        newWallet: This is the new state of the wallet after payment
        newWalletCom: A commitment of the new wallet
        rPrime: blinding value of commitment of new wallet
        paymentToken: A blind signature on the old wallet
        Output:
        NIZKProof: a proof that can be verified by the merchant during payment or closing protocol
    */
    pub fn prove<R: Rng>(&self, rng: &mut R, oldWallet: Wallet<E>, newWallet: Wallet<E>,
                         newWalletCom: Commitment<E>, rPrime: E::Fr, paymentToken: &Signature<E>) -> NIZKProof<E> {
        //Commitment phase
        //commit commitment
        let w_len = newWallet.as_fr_vec().len();
        let diff = self.comParams.pub_bases.len() - w_len;
        let max = match diff > 1 {
            true => w_len,
            false => self.comParams.pub_bases.len()
        };

        let (D, t) = CommitmentProof::<E>::prove_commitment(rng, &self.comParams, &newWallet.as_fr_vec(), None);

        //commit signature
        let zero = E::Fr::zero();
        let tOptional = match max > 4 {
            true => Some(vec!(t[1], zero, t[3].clone(), t[4].clone())),
            false => Some(vec!(t[1], zero, t[3].clone()))
        };
        let proofState = self.pk.prove_commitment(rng, &self.mpk, &paymentToken, tOptional, None);

        //commit range proof
        let rpStateBC = self.rpParams.prove_ul_commitment(rng, newWallet.bc.clone(), 3, None, None);
        let rpStateBM = self.rpParams.prove_ul_commitment(rng, newWallet.bm.clone(), 4, None, None);

        //Compute challenge
        let challenge = NIZKPublicParams::<E>::hash(proofState.a, vec! {D, rpStateBC.D, rpStateBM.D});

        //Response phase
        //response for signature
        let oldWalletVec = oldWallet.as_fr_vec();
        let sigProof = self.pk.prove_response(&proofState, challenge, &mut oldWalletVec.clone());

        //response commitment
        let newWalletVec = newWallet.as_fr_vec();
        let comProof = CommitmentProof::<E>::prove_response(&newWalletVec, &rPrime, D, &t, &challenge);

        //response range proof
        let mut vec01 = newWalletVec[0..2].to_vec();
        let mut vecWithout2 = vec01.clone();
        let mut vec3 = newWalletVec[3..].to_vec();
        vecWithout2.append(&mut vec3);
        let vec2 = newWalletVec[2].clone();
        vec01.push(vec2);
        if newWalletVec.len() > 4 {
            let mut vec4 = newWalletVec[4..].to_vec();
            vec01.append(&mut vec4);
        }
        let rpBC = self.rpParams.prove_ul_response(rPrime.clone(), newWalletCom.clone(), &rpStateBC, challenge.clone(), 3, vecWithout2.to_vec());
        let rpBM = self.rpParams.prove_ul_response(rPrime.clone(), newWalletCom.clone(), &rpStateBM, challenge.clone(), 4, vec01.to_vec());

        NIZKProof { sig: proofState.blindSig, sigProof, comProof, rpBC, rpBM }
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

///
/// Verify PoK for the opening of a commitment during the establishment protocol
///
pub fn verify_opening<E: Engine>(com_params: &CSMultiParams<E>, com: &E::G1, proof: &CommitmentProof<E>, channelId: &E::Fr, init_cust: i64, init_merch: i64) -> bool {
    let xvec: Vec<E::G1> = vec![proof.T.clone(), com.clone()];
    let challenge = util::hash_g1_to_fr::<E>(&xvec);

    // compute the
    let com_equal = proof.verify_proof(com_params, com, &challenge, Some(vec!{None, Some(channelId.clone()), None, Some(util::convert_int_to_fr::<E>(init_cust as i64)), Some(util::convert_int_to_fr::<E>(init_merch as i64))}));

    return com_equal;
}


#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{Bls12, Fr};
    use util::convert_int_to_fr;
    use ff::PrimeField;

    #[test]
    fn nizk_proof_works() {
        let rng = &mut rand::thread_rng();
        let channelId = Fr::rand(rng);
        let wpk = Fr::rand(rng);
        let wpkprime = Fr::rand(rng);
        let bc = rng.gen_range(100, 1000);
        let mut bc2 = bc.clone();
        let bm = rng.gen_range(100, 1000);
        let mut bm2 = bm.clone();
        let epsilon = rng.gen_range(1, 100);
        bc2 -= epsilon;
        bm2 += epsilon;
        let r = Fr::rand(rng);
        let rprime = Fr::rand(rng);

        let secParams = NIZKSecretParams::<Bls12>::setup(rng, 4);
        let wallet1 = Wallet { channelId: channelId, wpk, bc, bm, close: None };
        let commitment1 = secParams.pubParams.comParams.commit(&wallet1.as_fr_vec(), &r);
        let wallet2 = Wallet { channelId: channelId, wpk: wpkprime, bc: bc2, bm: bm2, close: None };
        let commitment2 = secParams.pubParams.comParams.commit(&wallet2.as_fr_vec(), &rprime);
        let blindPaymentToken = secParams.keypair.sign_blind(rng, &secParams.pubParams.mpk, commitment1.clone());
        let paymentToken = secParams.keypair.unblind(&r, &blindPaymentToken);

        let proof = secParams.pubParams.prove(rng, wallet1, wallet2,
                                              commitment2.clone(), rprime, &paymentToken);
        let fr = convert_int_to_fr::<Bls12>(epsilon);
        assert_eq!(secParams.verify(proof, fr, &commitment2, wpk), true);
    }

    #[test]
    fn nizk_proof_negative_value_works() {
        let rng = &mut rand::thread_rng();
        let channelId = Fr::rand(rng);
        let wpk = Fr::rand(rng);
        let wpkprime = Fr::rand(rng);
        let bc = rng.gen_range(100, 1000);
        let mut bc2 = bc.clone();
        let bm = rng.gen_range(100, 1000);
        let mut bm2 = bm.clone();
        let epsilon = rng.gen_range(-100, -1);
        bc2 -= epsilon;
        bm2 += epsilon;
        let r = Fr::rand(rng);
        let rprime = Fr::rand(rng);

        let secParams = NIZKSecretParams::<Bls12>::setup(rng, 4);
        let wallet1 = Wallet { channelId: channelId, wpk, bc, bm, close: None };
        let commitment1 = secParams.pubParams.comParams.commit(&wallet1.as_fr_vec(), &r);
        let wallet2 = Wallet { channelId: channelId, wpk: wpkprime, bc: bc2, bm: bm2, close: None };
        let commitment2 = secParams.pubParams.comParams.commit(&wallet2.as_fr_vec(), &rprime);
        let blindPaymentToken = secParams.keypair.sign_blind(rng, &secParams.pubParams.mpk, commitment1.clone());
        let paymentToken = secParams.keypair.unblind(&r, &blindPaymentToken);

        let proof = secParams.pubParams.prove(rng, wallet1, wallet2,
                                              commitment2.clone(), rprime, &paymentToken);
        let fr = convert_int_to_fr::<Bls12>(epsilon);
        assert_eq!(secParams.verify(proof, fr, &commitment2, wpk), true);
    }

    #[test]
    fn nizk_proof_close_works() {
        let rng = &mut rand::thread_rng();
        let channelId = Fr::rand(rng);
        let wpk = Fr::rand(rng);
        let wpkprime = Fr::rand(rng);
        let bc = rng.gen_range(100, 1000);
        let mut bc2 = bc.clone();
        let bm = rng.gen_range(100, 1000);
        let mut bm2 = bm.clone();
        let epsilon = rng.gen_range(1, 100);
        bc2 -= epsilon;
        bm2 += epsilon;
        let r = Fr::rand(rng);
        let rprime = Fr::rand(rng);

        let _closeToken = Fr::rand(rng);
        let secParams = NIZKSecretParams::<Bls12>::setup(rng, 5);
        let wallet1 = Wallet { channelId: channelId, wpk, bc, bm, close: None };
        let commitment1 = secParams.pubParams.comParams.commit(&wallet1.as_fr_vec(), &r);
        let wallet2 = Wallet { channelId: channelId, wpk: wpkprime, bc: bc2, bm: bm2, close: Some(_closeToken) };
        let commitment2 = secParams.pubParams.comParams.commit(&wallet2.as_fr_vec(), &rprime);
        let blindPaymentToken = secParams.keypair.sign_blind(rng, &secParams.pubParams.mpk, commitment1.clone());
        let paymentToken = secParams.keypair.unblind(&r, &blindPaymentToken);

        let blindCloseToken = secParams.keypair.sign_blind(rng, &secParams.pubParams.mpk, commitment2.clone());
        let closeToken = secParams.pubParams.pk.unblind(&rprime, &blindCloseToken);

        // verify the blind signatures
        let pk = secParams.keypair.get_public_key(&secParams.pubParams.mpk);
        assert!(pk.verify(&secParams.pubParams.mpk, &wallet1.as_fr_vec(), &paymentToken));

        println!("close => {}", &wallet2);
        assert!(pk.verify(&secParams.pubParams.mpk, &wallet2.as_fr_vec(), &closeToken));

        let proof = secParams.pubParams.prove(rng, wallet1, wallet2,
                                              commitment2.clone(), rprime, &paymentToken);

        assert_eq!(secParams.verify(proof, Fr::from_str(&epsilon.to_string()).unwrap(), &commitment2, wpk), true);
    }

    #[test]
    fn nizk_proof_false_statements() {
        let rng = &mut rand::thread_rng();
        let channelId = Fr::rand(rng);
        let wpk = Fr::rand(rng);
        let wpkprime = Fr::rand(rng);
        let bc = rng.gen_range(100, 1000);
        let mut bc2 = bc.clone();
        let bm = rng.gen_range(100, 1000);
        let mut bm2 = bm.clone();
        let epsilon = rng.gen_range(1, 100);
        bc2 -= epsilon;
        bm2 += epsilon;
        let r = Fr::rand(rng);
        let rprime = Fr::rand(rng);

        let secParams = NIZKSecretParams::<Bls12>::setup(rng, 4);
        let wallet1 = Wallet { channelId: channelId, wpk, bc, bm, close: None };

        let bc2Prime = bc.clone();
        let wallet3 = Wallet { channelId: channelId, wpk: wpkprime, bc: bc2Prime, bm: bm2, close: None };
        let commitment1 = secParams.pubParams.comParams.commit(&wallet1.as_fr_vec().clone(), &r);
        let commitment2 = secParams.pubParams.comParams.commit(&wallet3.as_fr_vec(), &rprime);
        let blindPaymentToken = secParams.keypair.sign_blind(rng, &secParams.pubParams.mpk, commitment1.clone());
        let paymentToken = secParams.keypair.unblind(&r, &blindPaymentToken);
        let proof = secParams.pubParams.prove(rng, wallet1.clone(), wallet3, commitment2.clone(), rprime, &paymentToken);
        assert_eq!(secParams.verify(proof, Fr::from_str(&epsilon.to_string()).unwrap(), &commitment2, wpk), false);

        let bm2Prime = bm.clone();
        let wallet4 = Wallet { channelId: channelId, wpk: wpkprime, bc: bc2, bm: bm2Prime, close: None };
        let commitment2 = secParams.pubParams.comParams.commit(&wallet4.as_fr_vec(), &rprime);
        let proof = secParams.pubParams.prove(rng, wallet1.clone(), wallet4, commitment2.clone(), rprime, &paymentToken);
        assert_eq!(secParams.verify(proof, Fr::from_str(&epsilon.to_string()).unwrap(), &commitment2, wpk), false);

        let wallet5 = Wallet { channelId: Fr::rand(rng), wpk: wpkprime, bc: bc2, bm: bm2, close: None };
        let commitment2 = secParams.pubParams.comParams.commit(&wallet5.as_fr_vec(), &rprime);
        let proof = secParams.pubParams.prove(rng, wallet1.clone(), wallet5, commitment2.clone(), rprime, &paymentToken);
        assert_eq!(secParams.verify(proof, Fr::from_str(&epsilon.to_string()).unwrap(), &commitment2, wpk), false);
    }

    #[test]
    fn nizk_proof_commitment_opening_works() {
        let rng = &mut rand::thread_rng();
        let channelId = Fr::rand(rng);
        let wpk = Fr::rand(rng);
        let t = Fr::rand(rng);

        let bc = rng.gen_range(100, 1000);
        let bm = rng.gen_range(100, 1000);
        let wallet = Wallet::<Bls12> { channelId: channelId, wpk: wpk, bc: bc, bm: bm, close: None };

        let secParams = NIZKSecretParams::<Bls12>::setup(rng, 4);
        let com = secParams.pubParams.comParams.commit(&wallet.as_fr_vec().clone(), &t);

        let com_proof = CommitmentProof::<Bls12>::new(rng, &secParams.pubParams.comParams,
                                                      &com.c, &wallet.as_fr_vec(), &t, &vec![1, 3, 4]);

        assert!(verify_opening(&secParams.pubParams.comParams, &com.c, &com_proof, &channelId.clone(), bc, bm));
    }

    #[test]
    fn nizk_proof_false_commitment() {
        let rng = &mut rand::thread_rng();
        let channelId = Fr::rand(rng);
        let wpk = Fr::rand(rng);
        let t = Fr::rand(rng);

        let bc = rng.gen_range(100, 1000);
        let bc2 = rng.gen_range(100, 1000);
        let bm = rng.gen_range(100, 1000);
        let wallet1 = Wallet::<Bls12> { channelId: channelId, wpk: wpk, bc: bc, bm: bm, close: None };
        let wallet2 = Wallet::<Bls12> { channelId: channelId, wpk: wpk, bc: bc2, bm: bm, close: None };

        let secParams = NIZKSecretParams::<Bls12>::setup(rng, 4);
        let com1 = secParams.pubParams.comParams.commit(&wallet1.as_fr_vec().clone(), &t);
        let com2 = secParams.pubParams.comParams.commit(&wallet2.as_fr_vec().clone(), &t);

        let com1_proof = CommitmentProof::<Bls12>::new(rng, &secParams.pubParams.comParams,
                                                       &com1.c, &wallet1.as_fr_vec(), &t, &vec![1, 3, 4]);

        assert!(verify_opening(&secParams.pubParams.comParams, &com1.c, &com1_proof, &channelId.clone(), bc, bm));
        assert!(!verify_opening(&secParams.pubParams.comParams, &com2.c, &com1_proof, &channelId.clone(), bc2, bm));
    }


    #[test]
    fn test_nizk_serialization() {
        let mut rng = &mut rand::thread_rng();

        let l = 5;
        let mpk = setup(&mut rng);
        let blindkeypair = BlindKeyPair::<Bls12>::generate(&mut rng, &mpk, l);
        let comParams = blindkeypair.generate_cs_multi_params(&mpk);
        let u = 256; //TODO: optimize u?
        let l = 8;
        let rpParams = ccs08::SecretParamsUL::setup_ul(rng, u, l, comParams.clone());

        let nizk_params = NIZKPublicParams { mpk: mpk, pk: blindkeypair.public, comParams: comParams, rpParams: rpParams.pubParams.clone() };

        let is_serialized = serde_json::to_vec(&nizk_params).unwrap();
        println!("NIZK Struct len: {}", is_serialized.len());

        // deserialize
    }
}
