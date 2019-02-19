use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::{encode,decode};
use bn::{Group, Fr, G1, G2, Gt};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use secp256k1;
use std::fmt;
// use serde-rustc-serialize-interop;

use serde::{Serialize, Serializer, ser::SerializeSeq, ser::SerializeStruct, Deserialize, Deserializer, de::Visitor, de::Error, de::SeqAccess};

pub fn serialize_generic_encodable<T, S>(object: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: rustc_serialize::Encodable,
    S: Serializer,
{
    let v = encode(&object, Infinite).unwrap();
    serializer.serialize_bytes(&v)
}

struct GOneVisitor;

impl<'de> Visitor<'de> for GOneVisitor {
    type Value = G1;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Sequence of bytes representing an element of G1")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> 
    {
        let mut bytes = Vec::new();

        loop {
            let tmp = seq.next_element::<u8>();
            if let Ok(Some(b)) = tmp {
                // println!("Byte = {:?}", b);
                bytes.push(b)
            } else {
                break;
            }
        } 

        Ok(decode(&bytes[..]).unwrap())
    }
}

struct GTwoVisitor;

impl<'de> Visitor<'de> for GTwoVisitor {
    type Value = G2;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Sequence of bytes representing an element of G2")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> 
    {
        let mut bytes = Vec::new();

        loop {
            let tmp = seq.next_element::<u8>();
            if let Ok(Some(b)) = tmp {
                // println!("Byte = {:?}", b);
                bytes.push(b)
            } else {
                break;
            }
        } 

        Ok(decode(&bytes[..]).unwrap())
    }
}

struct FieldVisitor;

impl<'de> Visitor<'de> for FieldVisitor {
    type Value = Fr;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Sequence of bytes representing an element of G2")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> 
    {
        let mut bytes = Vec::new();

        loop {
            let tmp = seq.next_element::<u8>();
            if let Ok(Some(b)) = tmp {
                // println!("Byte = {:?}", b);
                bytes.push(b)
            } else {
                break;
            }
        } 

        Ok(decode(&bytes[..]).unwrap())
    }
}

pub fn deserialize_g_one<'de, D>(deserializer: D) -> Result<G1, D::Error> 
where 
    D: Deserializer<'de>
{
    let a = deserializer.deserialize_seq(GOneVisitor);

    Ok(a.unwrap())
}

pub fn deserialize_g_two<'de, D>(deserializer: D) -> Result<G2, D::Error> 
where 
    D: Deserializer<'de>
{
    let a = deserializer.deserialize_seq(GTwoVisitor);

    Ok(a.unwrap())
}

pub fn deserialize_fr<'de, D>(deserializer: D) -> Result<Fr, D::Error> 
where 
    D: Deserializer<'de>
{
    let a = deserializer.deserialize_seq(FieldVisitor);

    Ok(a.unwrap())
}

pub fn serialize_generic_encodable_vec<T, S>(object: &Vec<T>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: rustc_serialize::Encodable,
{
        let mut seq = serializer.serialize_seq(Some(object.len()))?;
        for e in object {

            let v = encode(&e, Infinite).unwrap();
            seq.serialize_element(&v);
    	    // for i in v {
		    //     seq.serialize_element(&i)?;
		    // }
        }
        seq.end()
}

struct G1VecVisitor;

impl<'de> Visitor<'de> for G1VecVisitor {
    type Value = Vec<G1>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Sequence of byte encodings of G1")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {

        // println!("Hi G1VecVisitor");

        let mut vec = Vec::new();

        loop {
            let tmp = seq.next_element::<Vec<u8>>();
            if let Ok(Some(b)) = tmp {
                // println!("Byte = {:?}", b);
                vec.push(decode(&b[..]).unwrap());
            } else {
                break;
            }
        } 

        Ok(vec)
    }
}

struct G2VecVisitor;

impl<'de> Visitor<'de> for G2VecVisitor {
    type Value = Vec<G2>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Sequence of byte encodings of G2")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {

        // println!("Hi G2VecVisitor");

        let mut vec = Vec::new();

        loop {
            let tmp = seq.next_element::<Vec<u8>>();
            if let Ok(Some(b)) = tmp {
                // println!("Byte = {:?}", b);
                vec.push(decode(&b[..]).unwrap());
            } else {
                break;
            }
        } 

        Ok(vec)
    }
}

struct FrVecVisitor;

impl<'de> Visitor<'de> for FrVecVisitor {
    type Value = Vec<Fr>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Sequence of byte encodings of Fr")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {

        // println!("Hi FrVecVisitor");

        let mut vec = Vec::new();

        loop {
            let tmp = seq.next_element::<Vec<u8>>();
            // println!("tmp = {:?}", tmp);

            if let Ok(Some(b)) = tmp {
                // println!("Byte = {:?}", b);
                vec.push(decode(&b[..]).unwrap());
            } else {
                break;
            }
        } 

        Ok(vec)
    }
}

pub fn deserialize_g_one_vec<'de, D>(deserializer: D) -> Result<Vec<G1>, D::Error> 
where 
    D: Deserializer<'de>
{
    let a = deserializer.deserialize_seq(G1VecVisitor);

    Ok(a.unwrap())
}

pub fn deserialize_g_two_vec<'de, D>(deserializer: D) -> Result<Vec<G2>, D::Error> 
where 
    D: Deserializer<'de>
{
    let a = deserializer.deserialize_seq(G2VecVisitor);

    Ok(a.unwrap())
}

pub fn deserialize_fr_vec<'de, D>(deserializer: D) -> Result<Vec<Fr>, D::Error> 
where 
    D: Deserializer<'de>
{
    let a = deserializer.deserialize_seq(FrVecVisitor);

    Ok(a.unwrap())
}

pub fn serialize_bullet_proof<S>(bp_gens: &bulletproofs::BulletproofGens, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut state = serializer.serialize_seq(Some(2))?;
    state.serialize_element(&bp_gens.gens_capacity)?;
    state.serialize_element(&bp_gens.party_capacity)?;
    state.end()
}

struct BulletProofVisitor;

impl<'de> Visitor<'de> for BulletProofVisitor {
    type Value = BulletproofGens;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Sequence of usize for a BulletproofGens")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {

        let mut g_capacity: usize = 0;
        let mut p_capacity: usize = 0;

        let tmp = seq.next_element::<usize>();
        if let Ok(Some(b)) = tmp {
            g_capacity = b;
        }

        let tmp = seq.next_element::<usize>();
        if let Ok(Some(b)) = tmp {
            p_capacity = b;
        }


        Ok(BulletproofGens::new(g_capacity, p_capacity))
    }
}

pub fn deserialize_bullet_proof<'de, D>(deserializer: D) -> Result<bulletproofs::BulletproofGens, D::Error> 
where 
    D: Deserializer<'de>
{
    let a = deserializer.deserialize_seq(BulletProofVisitor);

    Ok(a.unwrap())
}