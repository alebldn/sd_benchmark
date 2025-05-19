use ark_bls12_381::Fr;
use digest::Digest;
use sha2::Sha256;
use ark_ff::PrimeField;
/// Struct that implements a PS Message.
#[derive(Clone, Debug)]
pub struct PSMessage {
    /// Index of the message in the array.
    index: usize,
    /// Scalar corresponding to the hash of the message.
    message: Fr,
}

impl PSMessage {

    /// Returns a new instance of a PSMessage.
    ///
    /// # Arguments
    /// * `index` - Index of the message in the array of messages.
    /// * `message` - Scalar corresponding to the hash of the message.
    ///
    /// # Returns
    /// An instance of PSMessage.
    pub fn new(index: usize, message: Fr) -> Self {
        Self { index, message }
    }

    /// Returns a new instance of a PSMessage given a byte array instead of the scalar.
    ///
    /// # Arguments
    /// * `index` - Index of the message in the array of messages.
    /// * `data` - Array of bytes that map the message.
    ///
    /// # Returns
    /// An instance of PSMessage.
    pub fn new_from_bytes(index: usize, data: &[u8]) -> Self {

        let binding = Sha256::digest(data);
        let msg_digest = binding.as_slice();

        Self { index, message: PrimeField::from_be_bytes_mod_order(msg_digest) }
    }

    /// Getter function to retrieve the index of the message.
    pub fn index(&self) -> usize {
        self.index
    }
    /// Getter function to retrieve the scalar nested inside the message.
    pub fn message(&self) -> Fr {
        self.message
    }
}