// ped92.rs
use rand::{thread_rng, Rng};
use pairing::{Engine, CurveProjective, CurveAffine};
use ff::Rand;

#[derive(Clone)]
pub struct CSPublicKey<E: Engine> {
    g: E::G2,
    h: E::G2,
}

#[derive(Clone)]
pub struct Commitment<E: Engine> {
    pub c: E::G2,
    pub r: E::Fr,
}

#[derive(Clone)]
pub struct CSMultiPublicKey<E: Engine> {
    pub pub_bases: Vec<E::G2>
}

//impl<E: Engine> fmt::Display for CSPublicKey<E> {
//    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//        let g_vec: Vec<u8> = encode(&self.g, Infinite).unwrap();
//        let h_vec: Vec<u8> = encode(&self.h, Infinite).unwrap();
//        let mut g_s = String::new();
//        for x in g_vec.iter() {
//            g_s = format!("{}{:x}", g_s, x);
//        }
//
//        let mut h_s = String::new();
//        for y in h_vec.iter() {
//            h_s = format!("{}{:x}", h_s, y);
//        }
//
//        write!(f, "PK : (g=0x{}, h=0x{})", g_s, h_s)
//    }
//}

//impl<E: Engine> fmt::Display for Commitment<E> {
//    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//        let c_vec: Vec<u8> = encode(&self.c, Infinite).unwrap();
//        let mut c_s = String::new();
//        for x in c_vec.iter() {
//            c_s = format!("{}{:x}", c_s, x);
//        }
//
//        let d_vec: Vec<u8> = encode(&self.r, Infinite).unwrap();
//        let mut d_s = String::new();
//        for x in d_vec.iter() {
//            d_s = format!("{}{:x}", d_s, x);
//        }
//        write!(f, "Commitment : (c=0x{}, r=0x{})", c_s, d_s)
//    }
//}

impl<E: Engine> CSPublicKey<E> {
    /*
Implements the setup algorithm for the Pedersen92 commitment scheme
*/
    pub fn setup<R: Rng>(rng: &mut R) -> Self {
        let g = E::G2::rand(rng);
        let h = E::G2::rand(rng);
        let pk = CSPublicKey { g, h };
        return pk;
    }

    /*
commit(pk, msg) -> cm where
- pk is the public key generated from setup()
- msg is the message structure for the commitment scheme
- cm is the output commitment message for the given message
*/
    pub fn commit<R: Rng>(&self, rng: &mut R, m: E::Fr, R: Option<E::Fr>) -> Commitment<E> {
        let r = R.unwrap_or(E::Fr::rand(rng));
        //let r = Fr::random(rng);

        //let m = msg.hash();
        let p = "commit -> m";
        // c = g^m * h^r
        let mut c = self.g.clone();
        c.mul_assign(m);
        let mut h = self.h.clone();
        h.mul_assign(r);
        c.add_assign(&h);
        // return (c, r) <- d=r
        let commitment = Commitment { c, r };

        // debugging
        return commitment;
    }

    /*
decommit(pk, cm, msg) -> bool where
- pk is the public key generated from setup()
- cm is the commitment
- m is the message to validate
- outputs T/F for whether the cm is a valid commitment to the msg
*/
    pub fn decommit(&self, cm: &Commitment<E>, m: E::Fr) -> bool {
        let p = "decommit -> m";

        let mut dm = self.g.clone();
        dm.mul_assign(m);
        let mut h = self.h.clone();
        h.mul_assign(cm.r.clone());
        dm.add_assign(&h);
        return dm == cm.c;
    }
}


impl<E: Engine> CSMultiPublicKey<E> {
    /*
    Implements the setup algorithm for the Pedersen92 commitment scheme over
    a vector of messages.
    */
    pub fn setup_gen_params<R: Rng>(rng: &mut R, len: usize) -> Self {
        let mut p: Vec<E::G2> = Vec::new();
        for i in 0..len {
            p.push(E::G2::rand(rng));
        }
        return CSMultiPublicKey { pub_bases: p };
    }

    pub fn commit<R: Rng>(&self, rng: &mut R, x: &Vec<E::Fr>, r: E::Fr) -> Commitment<E> {
        //let r = R.unwrap_or(Fr::random(rng));
        // c = g1^m1 * ... * gn^mn * h^r
        let mut c = self.pub_bases[0].clone();
        c.mul_assign(r);
        for i in 1..x.len() {
            let mut basis = self.pub_bases[i];
            basis.mul_assign(x[i]);
            c.add_assign(&basis);
        }
        // return (c, r) <- r
        Commitment { c, r }
    }

    pub fn decommit(&self, cm: &Commitment<E>, x: &Vec<E::Fr>) -> bool {
        let l = x.len();
        // pub_base[0] => h, x[0] => r
        // check that cm.r == x[0]
        let mut dc = self.pub_bases[0].clone();
        dc.mul_assign(cm.r.clone());
        for i in 1..l {
            let mut basis = self.pub_bases[i];
            basis.mul_assign(x[i]);
            dc.add_assign(&basis);
        }
        return dc == cm.c && cm.r == x[0];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{Bls12, Fr};
    use ff::Field;

    #[test]
    fn commit_one_message_works() {
        let rng = &mut thread_rng();
        let pk = CSPublicKey::<Bls12>::setup(rng);

        let m1 = Fr::rand(rng);
        let mut m2 = m1.clone();
        m2.add_assign(&Fr::one());
        let r = Fr::rand(rng);
        let c = pk.commit(rng, m1, Some(r));

        assert_eq!(true, pk.decommit(&c, m1));
        assert_eq!(false, pk.decommit(&c, m2));
    }

    #[test]
    fn commit_n_message_works() {
        let rng = &mut thread_rng();
        let len = 3;
        let csp = CSMultiPublicKey::<Bls12>::setup_gen_params(rng, len);

        let mut m: Vec<Fr> = Vec::new();
        for i in 0..len {
            m.push(Fr::rand(rng));
        }
        let r = m[0].clone();
        let c = csp.commit(rng, &m, r);

        assert_eq!(true, csp.decommit(&c, &m));
    }
}
