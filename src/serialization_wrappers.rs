use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::{encode,decode};
use bn::{Group, Fr, G1, G2, Gt};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use secp256k1;
use std::fmt;
use curve25519_dalek::ristretto::RistrettoPoint;
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


pub fn serialize_generic_encodable_option<T, S>(optional_object: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
where
    T: rustc_serialize::Encodable,
    S: Serializer,
{
    if let Some(object) = optional_object {
        let v = encode(&object, Infinite).unwrap();
        return serializer.serialize_bytes(&v);
    }
    serializer.serialize_none()
}

pub fn serialize_fixed_byte_array_option<S>(optional_object: &Option<[u8; 64]>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if let Some(object) = optional_object {
        return serializer.serialize_bytes(&object[..]);
    }
    serializer.serialize_none()
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
                bytes.push(b)
            } else {
                break;
            }
        } 

        Ok(decode(&bytes[..]).unwrap())
    }
}

struct GTargetVisitor;

impl<'de> Visitor<'de> for GTargetVisitor {
    type Value = Gt;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Sequence of bytes representing an element of Gt")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> 
    {
        let mut bytes = Vec::new();

        loop {
            let tmp = seq.next_element::<u8>();
            if let Ok(Some(b)) = tmp {
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
                bytes.push(b)
            } else {
                break;
            }
        } 

        Ok(decode(&bytes[..]).unwrap())
    }
}

struct OptionalFieldVisitor;

impl<'de> Visitor<'de> for OptionalFieldVisitor {
    type Value = Option<Fr>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Sequence of bytes representing an element of G2")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> 
    {
        let mut bytes = Vec::new();

        loop {
            let tmp = seq.next_element::<u8>();
            if let Ok(Some(b)) = tmp {
                bytes.push(b)
            } else {
                break;
            }
        } 

        Ok(Some(decode(&bytes[..]).unwrap()))
    }
    
    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(None)
    }
}

struct OptionalByteArrayVisitor;

impl<'de> Visitor<'de> for OptionalByteArrayVisitor {
    type Value = Option<[u8; 64]>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Sequence of bytes or nothing")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> 
    {
        let mut array: [u8; 64] = [00; 64];

        for i in 0..64 {
            let tmp = seq.next_element::<u8>();
        } 

        Ok(Some(array))
    }
    
    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(None)
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

pub fn deserialize_g_t<'de, D>(deserializer: D) -> Result<Gt, D::Error> 
where 
    D: Deserializer<'de>
{
    let a = deserializer.deserialize_seq(GTargetVisitor);

    Ok(a.unwrap())
}

pub fn deserialize_fr<'de, D>(deserializer: D) -> Result<Fr, D::Error> 
where 
    D: Deserializer<'de>
{
    let a = deserializer.deserialize_seq(FieldVisitor);

    Ok(a.unwrap())
}

pub fn deserialize_optional_fr<'de, D>(deserializer: D) -> Result<Option<Fr>, D::Error> 
where 
    D: Deserializer<'de>
{
    let a = deserializer.deserialize_any(OptionalFieldVisitor);

    Ok(a.unwrap())
}

pub fn deserialize_optional_fixed_64_byte_array<'de, D>(deserializer: D) -> Result<Option<[u8; 64]>, D::Error> 
where 
    D: Deserializer<'de>
{
    let a = deserializer.deserialize_option(OptionalByteArrayVisitor);

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

        let mut vec = Vec::new();

        loop {
            let tmp = seq.next_element::<Vec<u8>>();
            if let Ok(Some(b)) = tmp {
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

        let mut vec = Vec::new();

        loop {
            let tmp = seq.next_element::<Vec<u8>>();
            if let Ok(Some(b)) = tmp {
                vec.push(decode(&b[..]).unwrap());
            } else {
                break;
            }
        } 

        Ok(vec)
    }
}

struct GTargetVecVisitor;

impl<'de> Visitor<'de> for GTargetVecVisitor {
    type Value = Vec<Gt>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Sequence of byte encodings of G2")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {


        let mut vec = Vec::new();

        loop {
            let tmp = seq.next_element::<Vec<u8>>();
            if let Ok(Some(b)) = tmp {
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

        let mut vec = Vec::new();

        loop {
            let tmp = seq.next_element::<Vec<u8>>();

            if let Ok(Some(b)) = tmp {
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

pub fn deserialize_g_t_vec<'de, D>(deserializer: D) -> Result<Vec<Gt>, D::Error> 
where 
    D: Deserializer<'de>
{
    let a = deserializer.deserialize_seq(GTargetVecVisitor);

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


// --------------
// Fix for the tuple thing.  Not sure why its bugging, but it sure as hell is.

struct RangeProofVisitor;

impl<'de> Visitor<'de> for RangeProofVisitor {
    type Value = (bulletproofs::RangeProof, curve25519_dalek::ristretto::CompressedRistretto);

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Sequence of bytes representing a tuple, one range proof and one risteretto point")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {

        // the bytes representing the rangeproof
        let tmp = seq.next_element::<Vec<u8>>();
        let range_bytes = tmp.unwrap().unwrap();
        let range_proof = bulletproofs::RangeProof::from_bytes(&range_bytes[..]).unwrap();

        // the bytes representing the point
        let tmp2 = seq.next_element::<Vec<u8>>();
        let point_bytes = tmp2.unwrap().unwrap();
        let point = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&point_bytes[..]);
        
        Ok((range_proof, point))
    }
}

pub fn deserialize_range_proof<'de, D>(deserializer: D) -> Result<(bulletproofs::RangeProof, curve25519_dalek::ristretto::CompressedRistretto), D::Error> 
where 
    D: Deserializer<'de>
{
    let a = deserializer.deserialize_seq(RangeProofVisitor);

    Ok(a.unwrap())
}

struct RPointVisitor;

impl<'de> Visitor<'de> for RPointVisitor {
    type Value = curve25519_dalek::ristretto::RistrettoPoint;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Sequence of bytes representing a tuple, one range proof and one risteretto point")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {


        let mut point_bytes = Vec::new();
        loop {
            let tmp = seq.next_element::<u8>();
            if let Ok(Some(b)) = tmp {
                point_bytes.push(b)
            } else {
                break;
            }
        } 

        let point = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&point_bytes[..]);
        
        Ok(point.decompress().unwrap())
    }
}

pub fn deserialize_r_point<'de, D>(deserializer: D) -> Result<curve25519_dalek::ristretto::RistrettoPoint, D::Error> 
where 
    D: Deserializer<'de>
{
    let a = deserializer.deserialize_seq(RPointVisitor);

    Ok(a.unwrap())
}

// -------------
// These are hot fixes because secp256k1's implemenetation seems to be very very broken
// TODO THIS NEED TO BE FIXED UPSTREAM !!!

struct SignatureVisitor;

impl<'de> Visitor<'de> for SignatureVisitor {
    type Value = secp256k1::Signature;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Sequence of usize for a BulletproofGens")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {

        let mut bytes = Vec::new();
        loop {
            let tmp = seq.next_element::<u8>();
            if let Ok(Some(b)) = tmp {
                bytes.push(b)
            } else {
                break;
            }
        } 

        Ok(secp256k1::Signature::from_der(bytes.as_slice()).unwrap())
    }
}

pub fn deserialize_secp_signature<'de, D>(deserializer: D) -> Result<secp256k1::Signature, D::Error> 
where 
    D: Deserializer<'de>
{
    let a = deserializer.deserialize_seq(SignatureVisitor);

    Ok(a.unwrap())
}


struct PublicKeyVisitor;

impl<'de> Visitor<'de> for PublicKeyVisitor {
    type Value = secp256k1::PublicKey;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Sequence of usize for a BulletproofGens")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {

        let mut bytes = Vec::new();
        loop {
            let tmp = seq.next_element::<u8>();
            if let Ok(Some(b)) = tmp {
                bytes.push(b)
            } else {
                break;
            }
        } 

        Ok(secp256k1::PublicKey::from_slice(bytes.as_slice()).unwrap())
    }
}

pub fn deserialize_public_key<'de, D>(deserializer: D) -> Result<secp256k1::PublicKey, D::Error> 
where 
    D: Deserializer<'de>
{
    let a = deserializer.deserialize_seq(PublicKeyVisitor);

    Ok(a.unwrap())
}

struct SecretKeyVisitor;

impl<'de> Visitor<'de> for SecretKeyVisitor {
    type Value = secp256k1::SecretKey;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Sequence of usize for a BulletproofGens")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {

        let mut bytes = Vec::new();
        loop {
            let tmp = seq.next_element::<u8>();
            if let Ok(Some(b)) = tmp {
                bytes.push(b)
            } else {
                break;
            }
        } 

        Ok(secp256k1::SecretKey::from_slice(bytes.as_slice()).unwrap())
    }
}

pub fn deserialize_secret_key<'de, D>(deserializer: D) -> Result<secp256k1::SecretKey, D::Error> 
where 
    D: Deserializer<'de>
{
    let a = deserializer.deserialize_seq(SecretKeyVisitor);

    Ok(a.unwrap())
}
