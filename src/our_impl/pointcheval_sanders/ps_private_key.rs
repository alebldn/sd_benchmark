use ark_bls12_381::Fr;
use ark_serialize::CanonicalSerialize;
use serde::{Serialize, Serializer};
use serde::ser::SerializeSeq;

/// Struct that hosts all the data necessary for implementing a Private Key in the PS algorithm.
/// As described in "Efficient Redactable Signature and Application to Anonymous Credentials".
#[derive(Clone)]
pub struct PSPrivateKey {
    x: Fr,
    y_vec: Vec<Fr>
}

impl PSPrivateKey {

    /// Returns a new instance of a PSPrivateKey. Automatically handled in the PSSignature object.
    ///
    /// # Returns
    /// An instance of PSPrivateKey.
    pub fn new(x: Fr, y_vec: Vec<Fr>) -> Self {
        Self { x, y_vec }
    }

    /// Getter function to retrieve the x attribute from the private key.
    pub fn x(&self) -> Fr {
        self.x
    }

    /// Getter function to retrieve the vector of y attribute from the private key.
    pub fn y_vec(&self) -> &Vec<Fr> {
        &self.y_vec
    }
}


impl Serialize for PSPrivateKey {
    /// Implementation of the Serialize trait for PSPrivateKey.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer
    {
        let mut seq = serializer.serialize_seq(Some(4usize))?;

        let mut byte_vec: Vec<u8> = vec![];
        self.x.serialize_compressed(&mut byte_vec).unwrap();
        seq.serialize_element(&byte_vec)?;

        byte_vec.clear();
        self.y_vec.serialize_compressed(&mut byte_vec).unwrap();
        seq.serialize_element(&byte_vec)?;

        seq.end()

    }
}

