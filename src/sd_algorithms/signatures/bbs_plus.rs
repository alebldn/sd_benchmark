use serde_json::{Map, Value};
use zkryptium::bbsplus::keys::{BBSplusPublicKey, BBSplusSecretKey};
use zkryptium::schemes::algorithms::{BbsBls12381Sha256};
use zkryptium::schemes::generics::{PoKSignature, Signature};
use zkryptium::utils::util::bbsplus_utils::generate_random_secret;
use crate::common_data::SIGNATURE;
use crate::sd_algorithms::sd_algorithm::SdAlgorithm;
use crate::sd_algorithms::signatures::signature_sd_algorithm::SignatureSdAlgorithm;

/// Identifier for the nonce in the VC/VP.
pub const NONCE: &str = "nonce";
/// Identifier for the indices field in the VC/VP.
pub const INDICES: &str = "indices";


/// Struct that hosts an instance of a BBSPlus algorithm.
pub struct BBSPlusInstance;

impl SdAlgorithm for BBSPlusInstance {
    const ALGORITHM: &'static str = "BBS+";
}

impl SignatureSdAlgorithm for BBSPlusInstance {}

impl BBSPlusInstance {


    /// Given a raw VC containing a few fields and the credentialSubject field to include claims, create all the necessary data to create a VC using this algorithm.
    ///
    /// # Arguments
    /// * `raw_vc` - Template VC containing a credential.
    /// * `issuer_public_key` - Public key of the issuer used to generate the BBS+ signature.
    /// * `issuer_private_key` - Private key of the issuer used to generate the BBS+ signature.
    ///
    /// # Returns
    /// Returns a VC both in the form of a Map and in the form of an unsigned JWT.
    pub fn issue_vc(raw_vc: &Map<String, Value>, issuer_public_key: &BBSplusPublicKey, issuer_private_key: &BBSplusSecretKey) -> Result<(Map<String, Value>, String), String> {

        let mut vc = raw_vc.clone();

        let claims = Self::extract_claims(&vc)?;
        let claims_bytes = Self::convert_claims_to_bytes(claims)?;

        let signature = match Signature::<BbsBls12381Sha256>::sign(
            Some(&claims_bytes),
            issuer_private_key,
            issuer_public_key,
            None,
        ) {
            Ok(signature) => { signature }
            Err(err) => { return Err(format!("Error in producing signature [{}]", err.to_string()).to_string()) }
        };

        Self::serialize_and_insert(&mut vc, SIGNATURE.to_string(), &signature)?;
        let jwt = Self::encode_jwt(&vc)?;

        Ok((vc, jwt))
    }


    /// Given a VC, verify it using all the necessary data.
    ///
    /// # Arguments
    /// * `vc` - Verifiable Credential.
    /// * `issuer_public_key` - Issuer's public key to verify the BBS+ signature.
    ///
    /// # Returns
    /// Returns a string containing an error in case of failure.
    pub fn verify_vc(vc: &Map<String, Value>, issuer_public_key: &BBSplusPublicKey) -> Result<(), String> {

        let signature: Signature<BbsBls12381Sha256> = Self::get_and_decode(vc, SIGNATURE.to_string())?;
        let claims = Self::extract_claims(vc)?;
        let claims_bytes = Self::convert_claims_to_bytes(claims)?;

        match signature.verify(issuer_public_key, Some(&claims_bytes), None) {
            Ok(_) => { Ok(()) }
            Err(err) => { Err(format!("Signature verification failed [{err}]")) }
        }

    }


    /// Given a VC, and a set of disclosures, create a Verifiable Presentation accordingly.
    ///
    /// # Arguments
    /// * `vp` - Verifiable Credential.
    /// * `disclosures` - List of strings containing the names of the claims that are to be disclosed.
    /// * `issuer_public_key` - Issuer's public key necessary for computing the derived signature.
    /// * `holder_private_key` - Holder's private key necessary for proof of possession.
    ///
    /// # Returns
    /// Returns the VP both in form of a Map and in form of a signed JWT.
    pub fn issue_vp(vc: &Map<String, Value>, disclosures: &Vec<String>, issuer_public_key: &BBSplusPublicKey, holder_private_key: &impl AsRef<[u8]>) -> Result<(Map<String, Value>, String), String> {

        let mut vp: Map<String, Value> = vc.clone();
        let claims = Self::extract_claims(&mut vp)?.clone();
        let disclosed_indices = Self::filter_claims_by_disclosure_and_insert(&mut vp, disclosures)?;

        let nonce = generate_random_secret(32);
        let bbs_signature: Signature<BbsBls12381Sha256> = Self::get_and_decode(&mut vp, SIGNATURE.to_string())?;
        let claims = Self::convert_claims_to_bytes(&claims)?;

        let proof: PoKSignature<BbsBls12381Sha256> = match PoKSignature::<BbsBls12381Sha256>::proof_gen(
            &issuer_public_key,
            &bbs_signature.to_bytes(),
            None,
            Some(&nonce),
            Some(&claims),
            Some(&disclosed_indices),
        ) {
            Ok(proof) => { proof }
            Err(err) => { return Err(format!("Failed to generate POK Signature: [{err}]")) }
        };

        Self::serialize_and_insert(&mut vp, SIGNATURE.to_string(), &proof)?;
        Self::serialize_and_insert(&mut vp, INDICES.to_string(), &disclosed_indices)?;
        Self::serialize_and_insert(&mut vp, NONCE.to_string(), &nonce)?;

        let jwt = Self::encode_and_sign_jwt(&mut vp, &holder_private_key)?;

        Ok((vp, jwt))

    }


    /// Given a VP, verify it using all the necessary data.
    ///
    /// # Arguments
    /// * `jwt` - Verifiable Presentation encoded as a jwt.
    /// * `issuer_public_key` - Issuer's public key to verify the BBS+ signature.
    /// * `holder_public_key` - Holder's public key to verify the proof of possession.
    ///
    /// # Returns
    /// Returns a string containing an error in case of failure.
    pub fn verify_vp(signed_jwt: &String, issuer_public_key: &BBSplusPublicKey, holder_public_key: &impl AsRef<[u8]>) -> Result<(), String> {

        let vp: Map<String, Value> = Self::decode_and_verify_jwt(signed_jwt, &holder_public_key)?;
        let bbs_signature: PoKSignature<BbsBls12381Sha256> = Self::get_and_decode(&vp, SIGNATURE.to_string())?;
        let disclosed_indices: Vec<usize> = Self::get_and_decode(&vp, INDICES.to_string())?;
        let nonce: Vec<u8> = Self::get_and_decode(&vp, NONCE.to_string())?;

        let disclosed_claims: &Map<String, Value> = Self::extract_claims(&vp)?;
        let disclosed_claims: Vec<Vec<u8>> = Self::convert_claims_to_bytes(disclosed_claims)?;

        let result = bbs_signature.proof_verify(
            &issuer_public_key,
            Some(&disclosed_claims),
            Some(disclosed_indices.as_slice()),
            None,
            Some(nonce.as_slice()),
        );

        if result.is_ok() {
            Ok(())
        } else {
            Err("Signature verification failed.".to_string())
        }
    }
}


#[cfg(test)]
mod tests {
    use rand::Rng;
    use serde_json::{Map, Value};
    use zkryptium::bbsplus::ciphersuites::{BbsCiphersuite, Bls12381Sha256};
    use zkryptium::keys::pair::KeyPair;
    use zkryptium::schemes::algorithms::BBSplus;

    use crate::common_data::{CommonData, VC};
    use crate::sd_algorithms::signatures::bbs_plus::BBSPlusInstance;

    #[test]
    fn bbsplus() -> Result<(), String> {

        let value_raw_vc: Value = match serde_json::from_str::<Value>(VC) {
            Ok(value_vc) => { value_vc }
            Err(err) => { return Err(format!("[BBS+] Failed to parse Raw Verifiable Credential from string. [{err}]")); }
        };

        let mut raw_vc: Map<String, Value> = match serde_json::from_value::<Map<String, Value>>(value_raw_vc) {
            Ok(vc) => { vc }
            Err(err) => { return Err(format!("[BBS+] Failed to parse Raw Verifiable Credential from Value. [{err}]")); }
        };

        let raw_vc = &mut raw_vc;
        let mut rng = rand::rng();
        let key_material: Vec<u8> = (0..Bls12381Sha256::IKM_LEN).map(|_| rng.random()).collect();

        let issuer_keypair = match KeyPair::<BBSplus<Bls12381Sha256>>::generate(&key_material, None, None) {
            Ok(keypair) => { keypair }
            Err(err) => { return Err(format!("[BBS+] Error in issuing keypair [{err}]")) }
        };

        let issuer_sk = issuer_keypair.private_key();
        let issuer_pk = issuer_keypair.public_key();
        let (holder_public_key, holder_private_key) = CommonData::holder_keys()?;

        let (vc, _vc_jwt) = match BBSPlusInstance::issue_vc(raw_vc, &issuer_pk, &issuer_sk) {
            Ok(vc) => { vc }
            Err(err) => { return Err(format!("[BBS+] Failed to issue vc [{err}]."))}
        };

        match BBSPlusInstance::verify_vc(&vc, &issuer_pk) {
            Ok(_) => { println!("[BBS+] Successfully verified vc.")}
            Err(err) => { return Err(format!("[BBS+] Failed to verify vc [{err}]."))}
        };

        let disclosures = vec!["name", "birthdate"].iter().map(|x| x.to_string()).collect();

        let (_vp, vp_jwt) = match BBSPlusInstance::issue_vp(&vc, &disclosures, &issuer_pk, &holder_private_key) {
            Ok(vp) => { vp }
            Err(err) => { return Err(format!("[BBS+] Failed to issue vp: [{err}].")) }
        };

        match BBSPlusInstance::verify_vp(&vp_jwt, &issuer_pk, &holder_public_key) {
            Ok(_) => { println!("[BBS+] Successfully verified vp.")}
            Err(err) => { return Err(format!("[BBS+] Failed to verify vp [{err}].")) }
        };

        Ok(())
    }
}