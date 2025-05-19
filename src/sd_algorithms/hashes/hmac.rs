use josekit::jws::{HS256, JwsSigner};
use rand::Rng;
use serde_json::{Map, Value};

use crate::common_data::{CLAIMS, SIGNATURE};
use crate::sd_algorithms::hashes::hash_sd_algorithm::HashSdAlgorithm;
use crate::sd_algorithms::sd_algorithm::SdAlgorithm;

/// HMAC Key length in bytes.
const KEY_SIZE: usize = 32;   // 32 u8 = 32 * 8 = 256 bits
/// Identifier of the list of hashes as a field in the VC.
const HMACS: &str = "hmacs";
/// Name of the Key-Value Container as a field in the VC.
const KVC: &str = "kvc";


/// Struct that symbolizes an instance of a HMAC-based algorithm.
pub struct HmacInstance;

impl SdAlgorithm for HmacInstance {
    const ALGORITHM: &'static str = "HMAC";
}

impl HashSdAlgorithm for HmacInstance {}

impl HmacInstance {

    /// A function to randomly generate keys for HMACs.
    ///
    /// # Returns
    /// Returns a vector of bytes containing a single cryptographic symmetric key.
    fn generate_random_key() -> Vec<u8> {

        let mut bytes: Vec<u8> = vec![0; KEY_SIZE];
        let mut rng = rand::rng();
        rng.fill(&mut bytes[..]);

        bytes
    }


    /// Given an element name, an element field, and a cryptographic key, concatenate name and field and compute the resulting HMAC.
    ///
    /// # Arguments
    /// * `key` -  Name (identifier) of the element.
    /// * `value` - Value of the element.
    /// * `jwk` - Symmetric key for Hashing operations.
    ///
    /// # Returns
    /// Returns a result wrapping a successful HMAC computation or a string in case of failure.
    fn compute_hmac(key: &String, value: &String, jwk: &Vec<u8>) -> Result<String, String> {

        let signer = match HS256.signer_from_bytes(jwk) {
            Ok(signer) => { signer }
            Err(err) => { return Err(format!("Error in signer creation: [{err}]")); }
        };

        let mut text = key.clone();
        text.push(':');
        text.push_str(&value);

        let hmac_vec = match signer.sign(text.as_bytes()) {
            Ok(hmac) => { hmac }
            Err(err) => { return Err(format!("Error in signing \"{text}\": [{err}]")) }
        };

        Ok(multibase::Base::Base64Url.encode(hmac_vec))
    }


    /// High level verification of the Key-Value Container.
    ///
    /// # Arguments
    /// * `kvc` - Key-Value Container
    /// * `hmacs` - List of HMACS that are to be matched with the ones computed in this function.
    ///
    /// # Returns
    /// Returns a result containing a string in case of failure.
    fn verify_key_value_container(kvc: &Map<String, Value>, hmacs_value: &Value) -> Result<(), String> {
        fn decode_hmac_value(hmacs_value: &Value) -> Result<Vec<String>, String> {

            let mut hmacs = vec![];
            if let Value::Array(array) = hmacs_value {
                for element in array {
                    if let Value::String(hmac) = element {
                        hmacs.push(hmac.clone());
                    } else {
                        return Err("Non-String element in hmac array".to_string());
                    }
                }
            } else {
                return Err("Hmac value is not an array.".to_string());
            };

            Ok(hmacs)
        }

        let hmacs: Vec<String> = decode_hmac_value(&hmacs_value)?;

        for (field, array_value) in kvc {

            if let Value::Array(array) = array_value {
                let key = match array.get(0) {
                    None => { return Err("Key not found in key value container.".to_string()) }
                    Some(key) => { key }
                };
                let value = match array.get(1) {
                    None => { return Err("Value not found in key value container.".to_string()) }
                    Some(value) => { value }
                };

                match (key, value) {
                    (Value::String(key), Value::String(value)) => {
                        let jwk: Vec<u8> = match serde_json::from_str(key) {
                            Ok(jwk) => { jwk }
                            Err(err) => { return Err(format!("Error in decoding jwk: [{err}]")) }
                        };

                        let hmac = Self::compute_hmac(&field, value, &jwk)?;
                        if !hmacs.contains(&hmac) {
                            return Err("Hmac array does not contain hmac".to_string());
                        }
                    }
                    _ => { return Err("Either keys or values are not strings.".to_string())}
                }

            } else {
                return Err("Error, array field in key value container is not an array".to_string());
            }
        }

        Ok(())
    }


    /// Given a raw VC containing a few fields and the credentialSubject field to include claims, create all the necessary data to create a VC using this algorithm.
    ///
    /// # Arguments
    /// * `raw_vc` - Template VC containing a credential.
    /// * `issuer_private_key` - Private key of the issuer used to generate the signature of the list of hashes.
    ///
    /// # Returns
    /// Returns a VC both in the form of a Map and in the form of an unsigned JWT.
    pub fn issue_vc(raw_vc: &Map<String, Value>, issuer_private_key: &impl AsRef<[u8]>) -> Result<(Map<String, Value>, String), String> {

        let mut vc = raw_vc.clone();

        let claims: &Map<String, Value> = Self::extract_claims(&vc)?;
        let mut key_value_container: Map<String, Value> = Map::new();
        let mut hmacs: Vec<Value> = vec![];
        let mut hmac: String;

        for (field, value) in claims {
            if let Value::String(val) = value { // Only works with strings
                let jwk: Vec<u8> = Self::generate_random_key();
                let jwk_string = match serde_json::to_string(&jwk) {
                    Ok(jwk_string) => { jwk_string }
                    Err(err) => { return Err(format!("Error in conversion from jwk: [{err}]")) }
                };

                key_value_container.insert(field.clone(), Value::Array(vec![Value::String(jwk_string), value.clone()]));
                hmac = Self::compute_hmac(field, val, &jwk)?;
                hmacs.push(Value::String(hmac));
            }
        }

        let hmac_value: Value = Value::Array(hmacs);
        let signature: Vec<u8> = Self::derive_signature(hmac_value.to_string().as_bytes(), issuer_private_key)?;

        Self::serialize_and_insert(&mut vc, SIGNATURE.to_string(), &signature)?;
        Self::serialize_and_insert(&mut vc, HMACS.to_string(), &hmac_value)?;
        Self::serialize_and_insert(&mut vc, KVC.to_string(), &key_value_container)?;

        match vc.remove(CLAIMS) {
            None => { return Err("Claims removed should not be none here.".to_string()) }
            Some(_) => { }
        }

        let jwt = Self::encode_jwt(&vc)?;

        Ok((vc, jwt))
    }


    /// Given a VC, verify it using all the necessary data.
    ///
    /// # Arguments
    /// * `vc` - Verifiable Credential.
    /// * `issuer_public_key` - Issuer's public key to verify the signature of the list of hmacs.
    ///
    /// # Returns
    /// Returns a string containing an error in case of failure.
    pub fn verify_vc(vc: &Map<String, Value>, issuer_public_key: &impl AsRef<[u8]>) -> Result<(), String> {

        let key_value_container: Map<String, Value> = Self::get_and_decode(vc, KVC.to_string())?;
        let hmacs_value: Value = Self::get_and_decode(vc, HMACS.to_string())?;
        let signature: Vec<u8> = Self::get_and_decode(vc, SIGNATURE.to_string())?;

        Self::verify_key_value_container(&key_value_container, &hmacs_value)?;
        Self::verify_signature(hmacs_value.to_string().as_bytes(), &signature, issuer_public_key)?;

        Ok(())
    }


    /// Given a VC, and a set of disclosures, create a Verifiable Presentation accordingly.
    ///
    /// # Arguments
    /// * `vc` - Verifiable Credential.
    /// * `disclosures` - List of strings containing the names of the claims that are to be disclosed.
    /// * `holder_private_key` - Holder's private key necessary for proof of possession.
    ///
    /// # Returns
    /// Returns the VP both in form of a Map and in form of a signed JWT.
    pub fn issue_vp(vc: &Map<String, Value>, disclosures: &Vec<String>, holder_private_key: &impl AsRef<[u8]>) -> Result<(Map<String, Value>, String), String> {

        let mut vp: Map<String, Value> = vc.clone();

        let key_value_container: Map<String, Value> = Self::get_and_decode(&mut vp, KVC.to_string())?;
        let mut new_key_value_container: Map<String, Value> = Map::new();

        for (field, value) in key_value_container {
            if disclosures.contains(&field) {
                new_key_value_container.insert(field, value);
            }
        }

        Self::serialize_and_insert(&mut vp, KVC.to_string(), &new_key_value_container)?;

        let jwt: String = Self::encode_and_sign_jwt(&mut vp, holder_private_key)?;

        Ok((vp, jwt))
    }


    /// Given a VP, verify it using all the necessary data.
    ///
    /// # Arguments
    /// * `jwt` - Verifiable Presentation encoded as a jwt.
    /// * `issuer_public_key` - Issuer's public key to verify the signature of the list of hmacs.
    /// * `holder_public_key` - Holder's public key to verify the proof of possession.
    ///
    /// # Returns
    /// Returns a string containing an error in case of failure.
    pub fn verify_vp(jwt: &String, issuer_public_key: &impl AsRef<[u8]>, holder_public_key: &impl AsRef<[u8]>) -> Result<(), String> {

        let vp = Self::decode_and_verify_jwt(jwt, holder_public_key)?;
        let key_value_container: Map<String, Value> = Self::get_and_decode(&vp, KVC.to_string())?;
        let hmacs_value: Value = Self::get_and_decode(&vp, HMACS.to_string())?;
        let signature: Vec<u8> = Self::get_and_decode(&vp, SIGNATURE.to_string())?;

        Self::verify_key_value_container(&key_value_container, &hmacs_value)?;
        Self::verify_signature(hmacs_value.to_string().as_bytes(), &signature, issuer_public_key)?;

        Ok(())
    }

}


#[cfg(test)]
mod tests {
    use serde_json::{Map, Value};

    use crate::common_data::{CommonData, VC};

    use super::*;

    #[test]
    fn hmac() -> Result<(), String> {

        let value_raw_vc: Value = match serde_json::from_str::<Value>(VC) {
            Ok(value_vc) => { value_vc }
            Err(err) => { return Err(format!("[HMAC] Failed to parse Raw Verifiable Credential from string. [{err}]")); }
        };

        let mut raw_vc: Map<String, Value> = match serde_json::from_value::<Map<String, Value>>(value_raw_vc) {
            Ok(vc) => { vc }
            Err(err) => { return Err(format!("[HMAC] Failed to parse Raw Verifiable Credential from Value. [{err}]")); }
        };

        let raw_vc = &mut raw_vc;
        let (holder_public_key, holder_private_key) = CommonData::holder_keys()?;
        let (issuer_public_key, issuer_private_key) = CommonData::issuer_keys()?;

        let (vc, _vc_jwt) = match HmacInstance::issue_vc(raw_vc, &issuer_private_key) {
            Ok((sd_jwt, key_value_container)) => { (sd_jwt, key_value_container) }
            Err(err) => { return Err(format!("[HMAC] Failed to issue vc [{err}]."))}
        };

        match HmacInstance::verify_vc(&vc, &issuer_public_key) {
            Ok(_) => { println!("[HMAC] Successfully verified vc.")}
            Err(err) => { return Err(format!("[HMAC] Failed to verify vc [{err}]."))}
        };

        let disclosures = vec!["name", "birthdate"].iter().map(|x| x.to_string()).collect();

        let (_vp, vp_jwt) = match HmacInstance::issue_vp(&vc, &disclosures, &holder_private_key) {
            Ok(vp_jwt) => { vp_jwt }
            Err(err) => { return Err(format!("[HMAC] Failed to issue verifiable presentation: [{err}].")) }
        };

        match HmacInstance::verify_vp(&vp_jwt, &issuer_public_key, &holder_public_key) {
            Ok(_) => { println!("[HMAC] Successfully verified vp.")}
            Err(err) => { return Err(format!("[HMAC] Failed to verify vp [{err}].")) }
        };

        Ok(())
    }
}