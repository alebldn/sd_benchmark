use ark_std::rand::rngs::StdRng;
use serde_json::{Map, Value};
use crate::common_data::SIGNATURE;

use crate::our_impl::pointcheval_sanders::ps_message::PSMessage;
use crate::our_impl::pointcheval_sanders::ps_private_key::PSPrivateKey;
use crate::our_impl::pointcheval_sanders::ps_public_key::PSPublicKey;
use crate::our_impl::pointcheval_sanders::ps_signature::PSSignature;
use crate::sd_algorithms::sd_algorithm::SdAlgorithm;
use crate::sd_algorithms::signatures::signature_sd_algorithm::SignatureSdAlgorithm;

/// Identifier for the field containing the Nonce in the VC/VP.
pub const NONCE: &str = "nonce";
/// Identifier for the field containing disclosed indices in the VP.
pub const INDICES: &str = "indices";

/// Struct to implement an instance of the PS algorithm.
pub struct PSInstance;

impl SdAlgorithm for PSInstance {
    const ALGORITHM: &'static str = "PS";
}

impl SignatureSdAlgorithm for PSInstance {}

impl PSInstance {

    /// Utility function to convert a map of claims into a vector of messages that is compatible with the algorithm.
    /// Each message structure contains both the hash of the original data and an index to identify the message with.
    ///
    /// # Arguments
    /// * `claims` - Map of claims to be converted.
    ///
    /// # Returns
    /// Returns a result containing either an array of converted messages or a string illustrating an error
    fn build_messages(claims: &Map<String, Value>) -> Result<Vec<PSMessage>, String> {
        let claims_bytes = Self::convert_claims_to_bytes(&claims)?;
        let messages: Vec<PSMessage> = claims_bytes.iter().enumerate().map(|(index, claim_bytes)| {
            PSMessage::new_from_bytes(index, claim_bytes.as_slice())
        }).collect();

        Ok(messages)
    }

    /// Utility function used to convert a map of disclosed claims into an array of messages compatible with the algorithm.
    ///
    /// # Arguments
    /// * `disclosed_indices` - Vector containing the indices of the messages contained in the map at the same position.
    /// * `disclosed_claims` - Map of disclosed claims to be converted.
    ///
    /// # Returns
    /// Returns a result containing either an array of converted messages or a string illustrating an error
    fn build_disclosed_messages(disclosed_indices: Vec<usize>, disclosed_claims: &Map<String, Value>) -> Result<Vec<PSMessage>, String> {
        let disclosed_claim_bytes = Self::convert_claims_to_bytes(&disclosed_claims)?;
        let disclosed_messages: Vec<PSMessage> = disclosed_indices.iter().zip(disclosed_claim_bytes).map(|(index, claim_bytes)| {
            PSMessage::new_from_bytes(index.clone(), claim_bytes.as_slice())
        }).collect();

        Ok(disclosed_messages)
    }


    /// Given a raw VC containing a few fields and the credentialSubject field to include claims, create all the necessary data to create a VC using this algorithm.
    ///
    /// # Arguments
    /// * `raw_vc` - Template VC containing a credential.
    /// * `issuer_private_key` - Private key of the issuer used to generate the signature of the list of hashes.
    /// * `rng` - Random Number Generator necessary to handle the underlying PS algorithm.
    ///
    /// # Returns
    /// Returns a VC both in the form of a Map and in the form of an unsigned JWT.
    pub fn issue_vc(raw_vc: &Map<String, Value>, issuer_private_key: &PSPrivateKey, rng: &mut StdRng) -> Result<(Map<String, Value>, String), String> {

        let mut raw_vc = raw_vc.clone();

        let claims = Self::extract_claims(&raw_vc)?;
        let messages = Self::build_messages(claims)?;

        let signature = match PSSignature::sign(
            issuer_private_key,
            &messages,
            rng,
        ) {
            Ok(signature) => { signature }
            Err(err) => { return Err(format!("Error in producing signature [{}]", err.to_string()).to_string()) }
        };

        Self::serialize_and_insert(&mut raw_vc, SIGNATURE.to_string(), &signature)?;
        let jwt: String = Self::encode_jwt(&raw_vc)?;

        Ok((raw_vc, jwt))
    }


    /// Given a VC, verify it using all the necessary data.
    ///
    /// # Arguments
    /// * `vc` - Verifiable Credential.
    /// * `issuer_public_key` - Issuer's public key to verify the signature of the list of hashes.
    ///
    /// # Returns
    /// Returns a string containing an error in case of failure.
    pub fn verify_vc(vc: &Map<String, Value>, issuer_public_key: &PSPublicKey) -> Result<(), String> {

        let signature: PSSignature = Self::get_and_decode(vc, SIGNATURE.to_string())?;
        let claims = Self::extract_claims(vc)?;
        let messages = Self::build_messages(claims)?;

        match PSSignature::verify(issuer_public_key, &signature, &messages) {
            Ok(_) => {}
            Err(err) => { return Err(format!("Signature verification failed [{err}]")); }
        };

        Ok(())

    }

    /// Given a VC, and a set of disclosures, create a Verifiable Presentation accordingly.
    ///
    /// # Arguments
    /// * `vc` - Verifiable Credential.
    /// * `disclosures` - List of strings containing the names of the claims that are to be disclosed.
    /// * `issuer_public_key` - Issuer's public key  necessary for deriving the signature.
    /// * `holder_private_key` - Holder's private key necessary for proof of possession.
    /// * `rng` - Random Number Generator necessary to handle the underlying PS algorithm.
    ///
    /// # Returns
    /// Returns the VP both in form of a Map and in form of a signed JWT.
    pub fn issue_vp(vc: &Map<String, Value>, disclosures: &Vec<String>, issuer_public_key: &PSPublicKey, holder_private_key: &impl AsRef<[u8]>, rng: &mut StdRng) -> Result<(Map<String, Value>, String), String> {

        let mut vp: Map<String, Value> = vc.clone();
        let claims = &Self::extract_claims(&mut vp)?.clone();
        let disclosed_indices = Self::filter_claims_by_disclosure_and_insert(&mut vp, disclosures)?;
        let signature = Self::get_and_decode(&mut vp, SIGNATURE.to_string())?;
        let messages = Self::build_messages(claims)?;
        let derived_signature: PSSignature = PSSignature::derive(issuer_public_key, &signature, &messages, &disclosed_indices, rng)?;

        Self::serialize_and_insert(&mut vp, SIGNATURE.to_string(), &derived_signature)?;
        Self::serialize_and_insert(&mut vp, INDICES.to_string(), &disclosed_indices)?;

        let jwt = Self::encode_and_sign_jwt(&mut vp, &holder_private_key)?;

        Ok((vp, jwt))

    }


    /// Given a VP, verify it using all the necessary data.
    ///
    /// # Arguments
    /// * `jwt` - Verifiable Presentation encoded as a jwt.
    /// * `issuer_public_key` - Issuer's public key to verify the signature of the list of hashes.
    /// * `holder_public_key` - Holder's public key to verify the proof of possession.
    ///
    /// # Returns
    /// Returns a string containing an error in case of failure.
    pub fn verify_vp(jwt: &String, issuer_public_key: &PSPublicKey, holder_public_key: &impl AsRef<[u8]>) -> Result<(), String> {

        let vp: Map<String, Value> = Self::decode_and_verify_jwt(jwt, &holder_public_key)?;
        let disclosed_indices: Vec<usize> = Self::get_and_decode(&vp, INDICES.to_string())?;
        let signature: PSSignature = Self::get_and_decode(&vp, SIGNATURE.to_string())?;
        let disclosed_claims: &Map<String, Value> = Self::extract_claims(&vp)?;
        let disclosed_messages: Vec<PSMessage> = Self::build_disclosed_messages(disclosed_indices, disclosed_claims)?;

        PSSignature::verify(issuer_public_key, &signature, &disclosed_messages)?;

        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;
    use serde_json::{Map, Value};

    use crate::common_data::{CommonData, VC};
    use crate::our_impl::pointcheval_sanders::ps_signature::PSSignature;
    use crate::sd_algorithms::sd_algorithm::SdAlgorithm;
    use crate::sd_algorithms::signatures::ps::PSInstance;

    #[test]
    fn test_vc() -> Result<(), String> {

        let value_raw_vc: Value = match serde_json::from_str::<Value>(VC) {
            Ok(value_vc) => { value_vc }
            Err(err) => { return Err(format!("[PS] Failed to parse Raw Verifiable Credential from string. [{err}]")); }
        };

        let mut raw_vc: Map<String, Value> = match serde_json::from_value::<Map<String, Value>>(value_raw_vc) {
            Ok(vc) => { vc }
            Err(err) => { return Err(format!("[PS] Failed to parse Raw Verifiable Credential from Value. [{err}]")); }
        };

        let raw_vc = &mut raw_vc;
        let claims = PSInstance::extract_claims(raw_vc)?;

        let mut rng = StdRng::from_entropy();
        let (issuer_sk, issuer_pk) = PSSignature::keygen(claims.len(), &mut rng)?;
        let (holder_public_key, holder_private_key) = CommonData::holder_keys()?;

        let (vc, _vc_jwt) = match PSInstance::issue_vc(raw_vc, &issuer_sk, &mut rng) {
            Ok(vc) => { vc }
            Err(err) => { return Err(format!("[PS] Failed to issue vc [{err}]."))}
        };

        match PSInstance::verify_vc(&vc, &issuer_pk) {
            Ok(_) => { println!("[PS] Successfully verified vc.")}
            Err(err) => { return Err(format!("[PS] Failed to verify vc [{err}]."))}
        };

        let disclosures = vec!["name", "birthdate"].iter().map(|x| x.to_string()).collect();

        let (_vp, vp_jwt) = match PSInstance::issue_vp(&vc, &disclosures, &issuer_pk, &holder_private_key, &mut rng) {
            Ok(vp) => { vp }
            Err(err) => { return Err(format!("[PS] Failed to issue vp: [{err}].")) }
        };

        match PSInstance::verify_vp(&vp_jwt, &issuer_pk, &holder_public_key) {
            Ok(_) => { println!("[PS] Successfully verified vp.")}
            Err(err) => { return Err(format!("[PS] Failed to verify vp [{err}].")) }
        };

        Ok(())
    }
}