// ped92.rs
use rand::Rng;
use pairing::{Engine, CurveProjective};
use ff::{Rand, Field, PrimeField};
use std::fmt;
use util::is_vec_g1_equal;
use serde::{Serialize, Deserialize};
use util;

#[derive(Clone)]
pub struct CSParams<E: Engine> {
    pub g: E::G1,
    pub h: E::G1,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as pairing::Engine>::G1: serde::Serialize"))]
#[serde(bound(deserialize = "<E as pairing::Engine>::G1: serde::Deserialize<'de>"))]
pub struct Commitment<E: Engine> {
    pub c: E::G1,
}

impl<E: Engine> PartialEq for Commitment<E> {
    fn eq(&self, other: &Commitment<E>) -> bool {
        self.c == other.c
    }
}


#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as pairing::Engine>::G1: serde::Serialize"))]
#[serde(bound(deserialize = "<E as pairing::Engine>::G1: serde::Deserialize<'de>"))]
pub struct CSMultiParams<E: Engine> {
    pub pub_bases: Vec<E::G1>
}

impl<E: Engine> PartialEq for CSMultiParams<E> {
    fn eq(&self, other: &CSMultiParams<E>) -> bool {
        is_vec_g1_equal::<E>(&self.pub_bases, &other.pub_bases)
    }
}


impl<E: Engine> fmt::Display for CSMultiParams<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {

        let mut y_str = String::new();
        let mut i = 0;
        for y in self.pub_bases.iter() {
            y_str = format!("{}\n{} => {}", y_str, i, y);
            i += 1;
        }

        write!(f, "CSMultiParams : (\n{}\n)", y_str)
    }
}

impl<E: Engine> fmt::Display for Commitment<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Commitment : (c={})", &self.c)
    }
}

impl<E: Engine> CSParams<E> {
    /*
Implements the setup algorithm for the Pedersen92 commitment scheme
*/
    pub fn setup<R: Rng>(rng: &mut R) -> Self {
        let g = E::G1::rand(rng);
        let h = E::G1::rand(rng);
        CSParams { g, h }
    }

    /*
commit(pk, msg) -> cm where
- pk is the public key generated from setup()
- msg is the message structure for the commitment scheme
- cm is the output commitment message for the given message
*/
    pub fn commit<R: Rng>(&self, rng: &mut R, m: E::Fr, R: Option<E::Fr>) -> Commitment<E> {
        let r = R.unwrap_or(E::Fr::rand(rng));

        // c = g^m * h^r
        let mut c = self.g.clone();
        c.mul_assign(m.clone());
        let mut h = self.h.clone();
        h.mul_assign(r.clone());
        c.add_assign(&h);

        Commitment { c }
    }

    /*
decommit(csp, cm, msg) -> bool where
- cm is the commitment
- m is the message to validate
- outputs T/F for whether the cm is a valid commitment to the msg
*/
    pub fn decommit(&self, cm: &Commitment<E>, m: &E::Fr, r: &E::Fr) -> bool {
        let mut dm = self.g.clone();
        dm.mul_assign(m.clone());
        let mut h = self.h.clone();
        h.mul_assign(r.clone());
        dm.add_assign(&h);
        dm == cm.c
    }
}


impl<E: Engine> CSMultiParams<E> {
    /*
    Implements the setup algorithm for the Pedersen92 commitment scheme over
    a vector of messages of length len.
    */
    pub fn setup_gen_params<R: Rng>(rng: &mut R, len: usize) -> Self {
        let mut p: Vec<E::G1> = Vec::new();
        // 1 extra base element for the random parameter
        for _i in 0..len + 1 {
            p.push(E::G1::rand(rng));
        }
        CSMultiParams { pub_bases: p }
    }

    pub fn commit(&self, x: &Vec<E::Fr>, r: &E::Fr) -> Commitment<E> {
        // c = g1^m1 * ... * gn^mn * h^r
        let mut c = self.pub_bases[0].clone();
        let p_len = self.pub_bases.len();
        c.mul_assign(r.clone());
        //println!("commit => x.len = {}, p.len = {}", x.len(), p_len);
        for i in 0..x.len() {
            if (i < p_len) {
                let mut basis = self.pub_bases[i + 1];
                basis.mul_assign(x[i]);
                c.add_assign(&basis);
            }
        }
        Commitment { c }
    }

    pub fn extend_commit(&self, com: &Commitment<E>, x: &E::Fr) -> Commitment<E> {
        // c = com * gn+1 ^ x
        let len = self.pub_bases.len();
        let mut c = self.pub_bases[len-1].clone();
        c.mul_assign(x.clone());
        c.add_assign(&com.c);

        return Commitment { c };
    }

    pub fn remove_commit(&self, com: &Commitment<E>, x: &E::Fr) -> Commitment<E> {
        // c = com * gn+1 ^ x
        let len = self.pub_bases.len();
        let mut c = self.pub_bases[len-1].clone();
        let xx = x.clone();
        c.mul_assign(xx);
        c.negate();
        c.add_assign(&com.c);

        return Commitment { c };
    }


    pub fn decommit(&self, cm: &Commitment<E>, x: &Vec<E::Fr>, r: &E::Fr) -> bool {
        let l = x.len();
        // pub_base[0] => h, x[0] => r
        let mut dc = self.pub_bases[0].clone();
        dc.mul_assign(r.clone());
        for i in 0..l {
            let mut basis = self.pub_bases[i+1];
            basis.mul_assign(x[i]);
            dc.add_assign(&basis);
        }
        return dc == cm.c;
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
<E as pairing::Engine>::G1: serde::Serialize, \
<E as pairing::Engine>::G2: serde::Serialize"
))]
#[serde(bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
<E as pairing::Engine>::G1: serde::Deserialize<'de>, \
<E as pairing::Engine>::G2: serde::Deserialize<'de>"
))]
pub struct CommitmentProof<E: Engine> {
    pub T: E::G1,
    pub z: Vec<E::Fr>,
}

impl<E: Engine> CommitmentProof<E> {
    pub fn new<R: Rng>(csprng: &mut R, com_params: &CSMultiParams<E>, com: &E::G1, wallet: &Vec<E::Fr>, r: &E::Fr, reveal_index: &Vec<usize>) -> Self {
        let mut rt = Vec::new();
        for i in 0..wallet.len() + 1 {
            if reveal_index.contains(&i) {
                rt.push(E::Fr::zero());
            } else {
                rt.push(E::Fr::rand(csprng));
            }
        }

        let (Tvals, t) = CommitmentProof::<E>::prove_commitment::<R>(csprng, com_params, wallet, Some(rt));

        // compute the challenge
        let x: Vec<E::G1> = vec![Tvals, com.clone()];
        let challenge = util::hash_g1_to_fr::<E>(&x);

        // compute the response
        CommitmentProof::<E>::prove_response(wallet, r, Tvals, &t, &challenge)
    }

    pub fn prove_commitment<R: Rng>(csprng: &mut R, com_params: &CSMultiParams<E>, wallet: &Vec<E::Fr>, tOptional: Option<Vec<E::Fr>>) -> (E::G1, Vec<E::Fr>) {
        let mut Tvals = E::G1::zero();
        assert!(wallet.len() <= com_params.pub_bases.len());
        let mut t = tOptional.unwrap_or(Vec::<E::Fr>::with_capacity(wallet.len() + 1));
        // aspects of wallet being revealed
        for i in 0..wallet.len() + 1 {
            if t.len() == i {
                t.push(E::Fr::rand(csprng));
            }
            let ti = t[i].clone();
            let mut gt = com_params.pub_bases[i].clone();
            gt.mul_assign(ti.into_repr());
            Tvals.add_assign(&gt);
        }
        (Tvals, t)
    }

    pub fn prove_response(wallet: &Vec<E::Fr>, r: &E::Fr, Tvals: E::G1, t: &Vec<E::Fr>, challenge: &E::Fr) -> CommitmentProof<E> {
        let mut z: Vec<E::Fr> = Vec::new();
        let mut z0 = r.clone();
        z0.mul_assign(&challenge);
        z0.add_assign(&t[0]);
        z.push(z0);
        for i in 1..t.len() {
            let mut zi = wallet[i - 1].clone();
            zi.mul_assign(&challenge);
            zi.add_assign(&t[i]);
            z.push(zi);
        }

        CommitmentProof {
            T: Tvals, // commitment challenge
            z: z, // response values
        }
    }

    pub fn verify_proof(&self, com_params: &CSMultiParams<E>, com: &<E as Engine>::G1, challenge: &E::Fr, revealOption: Option<Vec<Option<E::Fr>>>) -> bool {
        let mut comc = com.clone();
        let T = self.T.clone();
        comc.mul_assign(challenge.into_repr());
        comc.add_assign(&T);
        let mut x = E::G1::zero();
        let reveal = revealOption.unwrap_or(vec!{});
        let mut revealBool = true;
        for i in 0..self.z.len() {
            let mut base = com_params.pub_bases[i].clone();
            base.mul_assign(self.z[i].into_repr());
            x.add_assign(&base);

            if reveal.len() > i && reveal[i].is_some() {
                let mut el = reveal[i].unwrap();
                el.mul_assign(&challenge.clone());
                revealBool = revealBool && self.z[i] == el;
            }
        }
        revealBool && comc == x
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{Bls12, Fr, G1};
    use rand::thread_rng;
    use ff::Field;
    use wallet::Wallet;

    #[test]
    fn commit_one_message_works() {
        let rng = &mut thread_rng();
        let csp = CSParams::<Bls12>::setup(rng);

        let m1 = Fr::rand(rng);
        let mut m2 = m1.clone();
        m2.add_assign(&Fr::one());
        let r = Fr::rand(rng);
        let c = csp.commit(rng, m1, Some(r));

        assert_eq!(csp.decommit(&c, &m1, &r), true);
        assert_eq!(csp.decommit(&c, &m2, &r), false);
    }

    #[test]
    fn commit_n_message_works() {
        let rng = &mut thread_rng();
        let len = 3;
        let csp = CSMultiParams::<Bls12>::setup_gen_params(rng, len);

        let mut m: Vec<Fr> = Vec::new();
        for _i in 0..len {
            m.push(Fr::rand(rng));
        }
        let r = Fr::rand(rng);
        let c = csp.commit(&m, &r);

        assert_eq!(csp.decommit(&c, &m, &r), true);
        let mut r1 = r.clone();
        r1.add_assign(&Fr::one());
        assert_eq!(csp.decommit(&c, &m, &r1), false);
    }

    #[test]
    fn commit_variable_messages_works() {
        let rng = &mut thread_rng();
        let len = 5;
        let csp = CSMultiParams::<Bls12>::setup_gen_params(rng, len);

        let mut m1: Vec<Fr> = Vec::new();
        for _i in 0..len-1 {
            m1.push(Fr::rand(rng));
        }
        let extra_m = Fr::rand(rng);
        let r = Fr::rand(rng);

        let c1 = csp.commit(&m1, &r);

        assert_eq!(csp.decommit(&c1, &m1, &r), true);
        let mut r1 = r.clone();
        r1.add_assign(&Fr::one());
        assert_eq!(csp.decommit(&c1, &m1, &r1), false);

        // let's add another message
        let mut m2 = m1.clone();
        m2.push(extra_m);
        let c2 = csp.commit(&m2, &r);
        assert_eq!(csp.decommit(&c2, &m2, &r), true);
    }

    #[test]
    fn test_csp_basic_serialize() {
        let rng = &mut rand::thread_rng();
        let len = 5;
        let csp = CSMultiParams::<Bls12>::setup_gen_params(rng, len);

        let serialized = serde_json::to_string(&csp).unwrap();

        let _csp_des: CSMultiParams<Bls12> = serde_json::from_str(&serialized).unwrap();
    }

    #[test]
    fn test_proof_commitment() {
        let rng = &mut rand::thread_rng();
        let channelId = Fr::rand(rng);
        let wpk = Fr::rand(rng);
        let t = Fr::rand(rng);

        let bc = rng.gen_range(100, 1000);
        let bm = rng.gen_range(100, 1000);
        let wallet = Wallet::<Bls12> { channelId: channelId, wpk: wpk, bc: bc, bm: bm, close: None };

        let comParams = CSMultiParams::setup_gen_params(rng, 4);
        let com = comParams.commit(&wallet.as_fr_vec().clone(), &t);

        let proof = CommitmentProof::<Bls12>::new(rng, &comParams, &com.c, &wallet.as_fr_vec(), &t, &vec!{});

        let xvec: Vec<G1> = vec![proof.T.clone(), com.c];
        let challenge = util::hash_g1_to_fr::<Bls12>(&xvec);
        assert_eq!(proof.verify_proof(&comParams, &com.c, &challenge, None), true);
    }

    // add tests for extend/remove commits dynamically
}
