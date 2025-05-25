use digest::Digest;
use serde_json::{Map, Value};
use zkryptium::cl03::bases::Bases;
use zkryptium::cl03::ciphersuites::{CL3072Sha256, CLCiphersuite};
use zkryptium::cl03::keys::{CL03CommitmentPublicKey, CL03PublicKey, CL03SecretKey};
use zkryptium::schemes::algorithms::{CL03_CL3072_SHA256};
use zkryptium::schemes::generics::{PoKSignature, Signature};
use zkryptium::utils::message::cl03_message::CL03Message;

use crate::common_data::SIGNATURE;
use crate::sd_algorithms::sd_algorithm::SdAlgorithm;
use crate::sd_algorithms::signatures::signature_sd_algorithm::SignatureSdAlgorithm;

/// Indicator for the field containing the bases in the VC/VP.
const BASES: &str = "bases";
/// Indicator for the field containing the indices in the VC/VP.
const UNDISCLOSED_INDICES: &str = "indices";
/// Identifier for the field containing the length of the vector of messages to be signed.
const LEN: &str = "mlen";

pub struct CLInstance;

impl SdAlgorithm for CLInstance {
    const ALGORITHM: &'static str = "CL03";
}

impl SignatureSdAlgorithm for CLInstance {}

impl CLInstance {

    /// Utility function to convert the map of claims into a vector of CL03Messages.
    ///
    /// # Arguments:
    /// * `claims` - Claims to be mapped.
    ///
    /// # Returns
    /// Returns a result containing the vector of messages mapped from the claims or a string in case of error.
    fn convert_claims_to_messages<C: CLCiphersuite>(claims: &Map<String, Value>) -> Result<Vec<CL03Message>, String>
    where
        C::HashAlg: Digest,
    {
        let messages: Vec<CL03Message> = Self::convert_claims_to_bytes(&claims)?.iter().map(
            |claim_bytes| {
                CL03Message::map_message_to_integer_as_hash::<C>(claim_bytes.as_slice())
            }
        ).collect();

        Ok(messages)
    }

    /// Given a raw VC containing a few fields and the credentialSubject field to include claims, create all the necessary data to create a VC using this algorithm.
    ///
    /// # Arguments
    /// * `raw_vc` - Template VC containing a credential.
    /// * `issuer_public_key` - Issuer's public key to generate the CL03 signature.
    /// * `issuer_private_key` - Private key of the issuer used to generate the CL03 signature.
    ///
    /// # Returns
    /// Returns a VC both in the form of a Map and in the form of an unsigned JWT.
    pub fn issue_vc(raw_vc: &Map<String, Value>, issuer_public_key: &CL03PublicKey, issuer_private_key: &CL03SecretKey) -> Result<(Map<String, Value>, String), String> {

        let mut vc = raw_vc.clone();

        let claims = Self::extract_claims(&vc)?;
        let claims_len = claims.len();
        let bases = Bases::generate(issuer_public_key, claims_len);

        let messages: Vec<CL03Message> = CLInstance::convert_claims_to_messages::<CL3072Sha256>(&claims)?;

        let signature = Signature::<CL03_CL3072_SHA256>::sign_multiattr(
            issuer_public_key,
            issuer_private_key,
            &bases,
            &messages
        );

        Self::serialize_and_insert(&mut vc, SIGNATURE.to_string(), &signature)?;
        Self::serialize_and_insert(&mut vc, BASES.to_string(), &bases)?;
        let jwt = Self::encode_jwt(&vc)?;

        Ok((vc, jwt))

    }


    /// Given a VC, verify it using all the necessary data.
    ///
    /// # Arguments
    /// * `vc` - Verifiable Credential.
    /// * `issuer_public_key` - Issuer's public key to verify the CL03 signature.
    ///
    /// # Returns
    /// Returns a string containing an error in case of failure.
    pub fn verify_vc(vc: &Map<String, Value>, issuer_public_key: &CL03PublicKey) -> Result<(), String> {

        let signature: Signature<CL03_CL3072_SHA256> = Self::get_and_decode(vc, SIGNATURE.to_string())?;
        let claims = Self::extract_claims(vc)?;
        let messages = CLInstance::convert_claims_to_messages::<CL3072Sha256>(claims)?;
        let bases: Bases = Self::get_and_decode(vc, BASES.to_string())?;

        // Signature verification
        if !signature.verify_multiattr(issuer_public_key, &bases, &messages) {
            Err("Signature verification failed!".to_string())
        } else {
            Ok(())
        }
    }

    /// Given a VC, and a set of disclosures, create a Verifiable Presentation accordingly.
    ///
    /// # Arguments
    /// * `vc` - Verifiable Credential.
    /// * `disclosures` - List of strings containing the names of the claims that are to be disclosed.
    /// * `issuer_public_key` - Issuer's public key necessary for deriving the CL03 signature.
    /// * `commitment_pk` - Public key used to generate CL03 commitments.
    /// * `holder_private_key` - Holder's private key necessary for proof of possession.
    ///
    /// # Returns
    /// Returns the VP both in form of a Map and in form of a signed JWT.
    pub fn issue_vp(vc: &Map<String, Value>, disclosures: &Vec<String>, issuer_public_key: &CL03PublicKey, commitment_pk: &CL03CommitmentPublicKey, holder_private_key: &impl AsRef<[u8]>) -> Result<(Map<String, Value>, String), String> {

        let mut vp: Map<String, Value> = vc.clone();
        let claims = Self::extract_claims(&mut vp)?;
        let messages = CLInstance::convert_claims_to_messages::<CL3072Sha256>(claims)?;
        let messages_len = messages.len();

        let disclosed_indices: Vec<usize> = Self::filter_claims_by_disclosure_and_insert(&mut vp, disclosures)?;
        let undisclosed_indices: Vec<usize> = Self::complementary_indices(&disclosed_indices, messages_len);
        let cl_signature: Signature<CL03_CL3072_SHA256> = Self::get_and_decode(&mut vp, SIGNATURE.to_string())?;

        let bases: Bases = Self::get_and_decode(&mut vp, BASES.to_string())?;

        // Computation of a Zero-Knowledge proof-of-knowledge of a signature
        let signature_pok = PoKSignature::<CL03_CL3072_SHA256>::proof_gen(
            cl_signature.cl03Signature(),
            &commitment_pk,
            issuer_public_key,
            &bases,
            &messages,
            &undisclosed_indices, // to be changed
        );

        Self::serialize_and_insert(&mut vp, SIGNATURE.to_string(), &signature_pok)?;
        Self::serialize_and_insert(&mut vp, UNDISCLOSED_INDICES.to_string(), &undisclosed_indices)?;
        Self::serialize_and_insert(&mut vp, LEN.to_string(), &messages_len)?;

        let jwt = Self::encode_and_sign_jwt(&mut vp, &holder_private_key)?;

        // unfortunately verifier_commitment_pk does not implement Deserialize therefore I can't encode it in the jwt to match other algorithms' signatures.
        Ok((vp, jwt))
    }


    /// Given a VP, verify it using all the necessary data.
    ///
    /// # Arguments
    /// * `jwt` - Verifiable Presentation encoded as a jwt.
    /// * `issuer_public_key` - Issuer's public key to verify the signature of the list of hashes.
    /// * `verifier_commitment_pk` - Commitment public key previously used to generate CL03 commitments.
    /// * `holder_public_key` - Holder's public key to verify the proof of possession.
    ///
    /// # Returns
    /// Returns a string containing an error in case of failure.
    pub fn verify_vp(signed_jwt: &String, issuer_public_key: &CL03PublicKey, verifier_commitment_pk: &CL03CommitmentPublicKey, holder_public_key: &impl AsRef<[u8]>) -> Result<(), String> {

        let vp: Map<String, Value> = Self::decode_and_verify_jwt(signed_jwt, &holder_public_key)?;

        let bases: Bases = Self::get_and_decode(&vp, BASES.to_string())?;
        let signature: PoKSignature<CL03_CL3072_SHA256> = Self::get_and_decode(&vp, SIGNATURE.to_string())?;
        let undisclosed_indices: Vec<usize> = Self::get_and_decode(&vp, UNDISCLOSED_INDICES.to_string())?;
        let messages_len: usize = Self::get_and_decode(&vp, LEN.to_string())?;

        let disclosed_claims = Self::extract_claims(&vp)?;
        let disclosed_messages = CLInstance::convert_claims_to_messages::<CL3072Sha256>(&disclosed_claims)?;

        // Signature Proof of Knowledge verification
        let valid_proof = signature.proof_verify(
            verifier_commitment_pk,
            issuer_public_key,
            &bases,
            &disclosed_messages,
            &undisclosed_indices,
            messages_len,
        );

        if valid_proof {
            Ok(())
        } else {
            Err("Signature verification failed.".to_string())
        }
    }
}


#[cfg(test)]
mod tests {
    use serde_json::{Map, Value};
    use zkryptium::cl03::ciphersuites::CL3072Sha256;
    use zkryptium::cl03::keys::CL03CommitmentPublicKey;
    use zkryptium::keys::pair::KeyPair;
    use zkryptium::schemes::algorithms::CL03;

    use crate::common_data::{CommonData, VC};
    use crate::sd_algorithms::sd_algorithm::SdAlgorithm;
    use crate::sd_algorithms::signatures::cl::CLInstance;

    #[test]
    fn cl() -> Result<(), String> {

        let value_raw_vc: Value = match serde_json::from_str::<Value>(VC) {
            Ok(value_vc) => { value_vc }
            Err(err) => { return Err(format!("[CL03] Failed to parse Raw Verifiable Credential from string. [{err}]")); }
        };

        let mut raw_vc: Map<String, Value> = match serde_json::from_value::<Map<String, Value>>(value_raw_vc) {
            Ok(vc) => { vc }
            Err(err) => { return Err(format!("[CL03] Failed to parse Raw Verifiable Credential from Value. [{err}]")); }
        };

        let raw_vc = &mut raw_vc;

        let claims = CLInstance::extract_claims(raw_vc)?;

        let issuer_keypair = KeyPair::<CL03<CL3072Sha256>>::generate();
        let issuer_sk = issuer_keypair.private_key();
        let issuer_pk = issuer_keypair.public_key();
        let (holder_public_key, holder_private_key) = CommonData::holder_keys()?;

        // Generation of a Commitment Public Key for the computation of the SPoK
        let commitment_pk = CL03CommitmentPublicKey::generate::<CL3072Sha256>(
            Some(issuer_pk.N.clone()),
            Some(claims.len()),
        );

        let (vc, _vc_jwt) = match CLInstance::issue_vc(raw_vc, issuer_pk, issuer_sk) {
            Ok(vc) => { vc }
            Err(err) => { return Err(format!("[CL03] Failed to issue vc [{err}]."))}
        };

        match CLInstance::verify_vc(&vc, &issuer_pk) {
            Ok(_) => { println!("[CL03] Successfully verified vc.")}
            Err(err) => { return Err(format!("[CL03] Failed to verify vc [{err}]."))}
        };

        let disclosures = vec!["name", "birthdate"].iter().map(|x| x.to_string()).collect();


        let (_vp, vp_jwt) = match CLInstance::issue_vp(&vc, &disclosures, &issuer_pk, &commitment_pk, &holder_private_key) {
            Ok(vp) => { vp }
            Err(err) => { return Err(format!("[CL03] Failed to issue vp: [{err}].")) }
        };

        match CLInstance::verify_vp(&vp_jwt, &issuer_pk, &commitment_pk, &holder_public_key) {
            Ok(_) => { println!("[CL03] Successfully verified vp.")}
            Err(err) => { return Err(format!("[CL03] Failed to verify vp [{err}].")) }
        };

        Ok(())
    }
}