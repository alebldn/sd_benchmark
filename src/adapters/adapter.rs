use serde_json::{Map, Value};

/// Adapter trait to level heterogeneous algorithm instances to execute different instances using the same notation.
pub trait Adapter {

    /// Retrieve the name of the algorithm.
    ///
    /// # Returns
    /// A string containing the name of the algorithm.
    fn sd_algorithm(&self) -> String;


    /// Create a new instance of the algorithm.
    ///
    /// # Arguments
    /// * `claims_len` - Amount of claims to be included in the VC.
    ///
    /// # Returns
    /// Returns a new instance of the Selective Disclosure algorithm for the corresponding adapter that implements this trait.
    fn new(claims_len: usize) -> Result<Self, String> where Self: Sized;

    /// Issues a new VC.
    ///
    /// # Arguments
    /// * `raw_vc` - Skeleton of a VC to be decorated with all the methods to create Verifiable Credentials.
    ///
    /// # Returns
    /// Returns a result containing a map of the VC and the encoded jwt or a string highlighting an error, if it occurs.
    fn issue_vc(&self, raw_vc: &Map<String, Value>) -> Result<(Map<String, Value>, String), String>;


    /// Verifies the VC.
    ///
    /// # Arguments
    /// * `vc` - Verifiable Credential to be verified.
    ///
    /// # Returns
    /// Returns a result with a string illustrating an error, if this happens.
    fn verify_vc(&self, vc: &Map<String, Value>) -> Result<(), String>;


    /// Given a VC and a list of disclosures, generate a Verifiable Presentation.
    ///
    /// # Arguments
    /// * `vc` - Verifiable Credential from which the VP must be generated.
    /// * `disclosures` - Array containing the identifiers of the claims to disclose.
    ///
    /// # Returns
    /// Returns a result containing a map of the VP and the encoded jwt or a string highlighting an error, if it occurs.
    fn issue_vp(&self, vc: &Map<String, Value>, disclosures: &Vec<String>) -> Result<(Map<String, Value>, String), String>;


    /// Given a VP, verify it.
    ///
    /// # Arguments
    /// * `vp_jwt` - jwt of the Verifiable Presentation to be verified.
    ///
    /// # Returns
    /// Returns a result containing a string illustrating an error, if it occurs.
    fn verify_vp(&self, vp_jwt: &String) -> Result<(), String>;


    /// Retrieve the issuer's cryptographic key material.
    ///
    /// # Returns
    /// Returns a result containing the encodings of the issuer's public key and secret key respectively, or a string highlighting an error, if it occurs.
    fn issuer_keypair(&self,) -> Result<(String, String), String>;
}
