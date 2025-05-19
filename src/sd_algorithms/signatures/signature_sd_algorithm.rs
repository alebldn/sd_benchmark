#[allow(dead_code)]
pub trait SignatureSdAlgorithm {
    /// Function that, taken in input a set of indices, and a maximum value, returns an array containing the complementary values.
    /// # Arguments
    /// * `disclosed_indices` - Vector containing the disclosed indices.
    /// * `issuer_public_key` - Maximum size of the indices vector (not to be confused with the disclosed_indices vector).
    ///
    /// # Returns
    /// Returns a complementary vector containing all the indices that are not included in the input vector.
    fn complementary_indices(disclosed_indices: &Vec<usize>, len: usize) -> Vec<usize> {
        let mut undisclosed_indices: Vec<usize> = vec![];

        for index in 0..len {
            if !disclosed_indices.contains(&index) {
                undisclosed_indices.push(index);
            }
        }

        undisclosed_indices
    }
}