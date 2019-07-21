extern crate pairing;

use super::*;
use pairing::{Engine, CurveProjective};
use ff::PrimeField;

#[derive(Clone)]
pub struct Wallet<E: Engine> {
    pub pkc: E::Fr,
    pub wpk: E::Fr,
    pub bc: i32,
    pub bm: i32,
}

impl<E: Engine> Wallet<E> {
    pub fn as_fr_vec(&self) -> Vec<E::Fr> {
        vec!(self.pkc, self.wpk, E::Fr::from_str(&self.bc.to_string()).unwrap(), E::Fr::from_str(&self.bm.to_string()).unwrap())
    }
}
