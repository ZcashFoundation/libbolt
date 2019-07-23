// ped92.rs
use rand::{thread_rng, Rng};
use pairing::{Engine, CurveProjective};
use ff::Rand;

#[derive(Clone)]
pub struct CSParams<E: Engine> {
    pub g: E::G1,
    pub h: E::G1,
}

#[derive(Clone)]
pub struct Commitment<E: Engine> {
    pub c: E::G1,
}

#[derive(Clone)]
pub struct CSMultiParams<E: Engine> {
    pub pub_bases: Vec<E::G1>
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
        for i in 0..len + 1 {
            p.push(E::G1::rand(rng));
        }
        // extra base used when extending a commitment
        // p.push(E::G1::rand(rng));
        CSMultiParams { pub_bases: p }
    }

    pub fn commit(&self, x: &Vec<E::Fr>, r: &E::Fr) -> Commitment<E> {
        // c = g1^m1 * ... * gn^mn * h^r
        let mut c = self.pub_bases[0].clone();
        c.mul_assign(r.clone());
        for i in 0..x.len() {
            let mut basis = self.pub_bases[i+1];
            basis.mul_assign(x[i]);
            c.add_assign(&basis);
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
