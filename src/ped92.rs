// ped92.rs
use rand::{thread_rng, Rng};
use pairing::{Engine, CurveProjective};
use ff::Rand;

#[derive(Clone)]
pub struct CSParams<E: Engine> {
    pub g1: E::G1,
    pub g2: E::G2,
    pub h1: E::G1,
    pub h2: E::G2,
}

#[derive(Clone)]
pub struct Commitment<E: Engine> {
    pub c1: E::G1,
    pub c2: E::G2
}

#[derive(Clone)]
pub struct CSMultiParams<E: Engine> {
    pub pub_bases1: Vec<E::G1>,
    pub pub_bases2: Vec<E::G2>
}

//impl<E: Engine> fmt::Display for CSParams<E> {
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
//        write!(f, "CSP : (g=0x{}, h=0x{})", g_s, h_s)
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

impl<E: Engine> CSParams<E> {
    /*
Implements the setup algorithm for the Pedersen92 commitment scheme
*/
    pub fn setup<R: Rng>(rng: &mut R) -> Self {
        let g1 = E::G1::rand(rng);
        let g2 = E::G2::rand(rng);
        let h1 = E::G1::rand(rng);
        let h2 = E::G2::rand(rng);
        let csp = CSParams { g1, g2, h1, h2 };
        return csp;
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
        let mut c1 = self.g1.clone();
        c1.mul_assign(m.clone());
        let mut h1 = self.h1.clone();
        h1.mul_assign(r.clone());
        c1.add_assign(&h1);

        // c = g^m * h^r
        let mut c2 = self.g2.clone();
        c2.mul_assign(m);
        let mut h2 = self.h2.clone();
        h2.mul_assign(r);
        c2.add_assign(&h2);

        Commitment { c1, c2 }
    }

    /*
decommit(csp, cm, msg) -> bool where
- cm is the commitment
- m is the message to validate
- outputs T/F for whether the cm is a valid commitment to the msg
*/
    pub fn decommit(&self, cm: &Commitment<E>, m: &E::Fr, r: &E::Fr) -> bool {
        let mut dm1 = self.g1.clone();
        dm1.mul_assign(m.clone());
        let mut h1 = self.h1.clone();
        h1.mul_assign(r.clone());
        dm1.add_assign(&h1);

        let mut dm2 = self.g2.clone();
        dm2.mul_assign(m.clone());
        let mut h2 = self.h2.clone();
        h2.mul_assign(r.clone());
        dm2.add_assign(&h2);
        return dm2 == cm.c2 && dm1 == cm.c1;
    }
}


impl<E: Engine> CSMultiParams<E> {
    /*
    Implements the setup algorithm for the Pedersen92 commitment scheme over
    a vector of messages of length len.
    */
    pub fn setup_gen_params<R: Rng>(rng: &mut R, len: usize) -> Self {
        let mut p1: Vec<E::G1> = Vec::new();
        let mut p2: Vec<E::G2> = Vec::new();
        // 1 extra base element for the random parameter
        for i in 0..len + 1 {
            p1.push(E::G1::rand(rng));
            p2.push(E::G2::rand(rng));
        }
        return CSMultiParams { pub_bases1: p1, pub_bases2: p2 };
    }

    pub fn commit(&self, x: &Vec<E::Fr>, r: &E::Fr) -> Commitment<E> {
        // c = g1^m1 * ... * gn^mn * h^r
        let mut c1 = self.pub_bases1[0].clone();
        let mut c2 = self.pub_bases2[0].clone();
        c1.mul_assign(r.clone());
        c2.mul_assign(r.clone());
        for i in 0..x.len() {
            let mut basis1 = self.pub_bases1[i+1];
            basis1.mul_assign(x[i]);
            c1.add_assign(&basis1);
            let mut basis2 = self.pub_bases2[i+1];
            basis2.mul_assign(x[i]);
            c2.add_assign(&basis2);
        }
        Commitment { c1, c2 }
    }

    pub fn decommit(&self, cm: &Commitment<E>, x: &Vec<E::Fr>, r: &E::Fr) -> bool {
        let l = x.len();
        // pub_base[0] => h, x[0] => r
        let mut dc1 = self.pub_bases1[0].clone();
        let mut dc2 = self.pub_bases2[0].clone();
        dc1.mul_assign(r.clone());
        dc2.mul_assign(r.clone());
        for i in 0..l {
            let mut basis1 = self.pub_bases1[i+1];
            basis1.mul_assign(x[i]);
            dc1.add_assign(&basis1);
            let mut basis2 = self.pub_bases2[i+1];
            basis2.mul_assign(x[i]);
            dc2.add_assign(&basis2);
        }
        return dc2 == cm.c2 && dc1 == cm.c1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{Bls12, Fr};
    use ff::Field;

    #[test]
    #[ignore]
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
    #[ignore]
    fn commit_n_message_works() {
        let rng = &mut thread_rng();
        let len = 3;
        let csp = CSMultiParams::<Bls12>::setup_gen_params(rng, len);

        let mut m: Vec<Fr> = Vec::new();
        for i in 0..len {
            m.push(Fr::rand(rng));
        }
        let r = Fr::rand(rng);
        let c = csp.commit(&m, &r);

        assert_eq!(csp.decommit(&c, &m, &r), true);
        let mut r1 = r.clone();
        r1.add_assign(&Fr::one());
        assert_eq!(csp.decommit(&c, &m, &r1), false);
    }
}
