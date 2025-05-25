use ark_bls12_381::{G1Affine, G2Affine};
use ark_serialize::CanonicalSerialize;
use serde::{Serialize, Serializer};
use serde::ser::SerializeSeq;

/// Struct that hosts all the data necessary for implementing a Public Key in the PS algorithm.
/// As described in "Efficient Redactable Signature and Application to Anonymous Credentials".
#[derive(Clone)]
pub struct PSPublicKey {
    g: G1Affine,
    g_tilde: G2Affine,
    capital_x: G1Affine,
    capital_y_vec: Vec<(G1Affine, G2Affine)>,
    capital_z_matrix: Vec<Vec<G1Affine>>,
}

impl PSPublicKey {

    /// Returns a new instance of a PSPublicKey. Automatically handled in the PSSignature object.
    ///
    /// # Returns
    /// An instance of PSPrivateKey.
    pub fn new(g: G1Affine, g_tilde: G2Affine, capital_x: G1Affine, capital_y_vec: Vec<(G1Affine, G2Affine)>, capital_z_matrix: Vec<Vec<G1Affine>>) -> Self {
        Self { g, g_tilde, capital_x, capital_y_vec, capital_z_matrix }
    }
    /// Getter function to retrieve the g attribute from the public key.
    pub fn g(&self) -> G1Affine {
        self.g
    }
    /// Getter function to retrieve the g_tilde attribute from the public key.
    pub fn g_tilde(&self) -> G2Affine {
        self.g_tilde
    }
    /// Getter function to retrieve the X attribute from the public key.
    pub fn capital_x(&self) -> G1Affine {
        self.capital_x
    }
    /// Getter function to retrieve the vector of Y attribute from the public key.
    pub fn capital_y_vec(&self) -> &Vec<(G1Affine, G2Affine)> {
        &self.capital_y_vec
    }
    /// Getter function to retrieve the matrix of Z attribute from the public key.
    pub fn capital_z_matrix(&self) -> &Vec<Vec<G1Affine>> {
        &self.capital_z_matrix
    }
}

impl Serialize for PSPublicKey {
    /// Implementation of the Serialize trait for PSPublicKey.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer
    {
        let mut seq = serializer.serialize_seq(Some(4usize))?;

        let mut byte_vec: Vec<u8> = vec![];
        self.g.serialize_compressed(&mut byte_vec).unwrap();
        seq.serialize_element(&byte_vec)?;

        byte_vec.clear();
        self.g_tilde.serialize_compressed(&mut byte_vec).unwrap();
        seq.serialize_element(&byte_vec)?;

        byte_vec.clear();
        self.capital_x.serialize_compressed(&mut byte_vec).unwrap();
        seq.serialize_element(&byte_vec)?;

        byte_vec.clear();
        self.capital_y_vec.serialize_compressed(&mut byte_vec).unwrap();
        seq.serialize_element(&byte_vec)?;

        byte_vec.clear();
        self.capital_z_matrix.serialize_compressed(&mut byte_vec).unwrap();
        seq.serialize_element(&byte_vec)?;

        seq.end()

    }
}

