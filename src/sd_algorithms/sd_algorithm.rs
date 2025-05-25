use josekit::jws::{JwsHeader, ES256};
use josekit::jwt;
use josekit::jwt::JwtPayload;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{Map, Value};
use crate::common_data::CLAIMS;

/// Trait that implements several methods shared across different algorithm instances.
pub trait SdAlgorithm {

    /// Each algorithm is identified by this unique string.
    const ALGORITHM: &'static str;

    /// A function that given either a VC or a VP in the form of a Map, returns the claims included in it.
    ///
    /// # Arguments
    /// * `map` - VC or VP from which it's necessary to retrieve the claims.
    ///
    /// # Returns
    /// Returns a result containing either the claims as a Map, or a string representing an error.
    fn extract_claims(map: &Map<String, Value>) -> Result<&Map<String, Value>, String> {
        let claims_value = match map.get(CLAIMS) {
            None => { return Err("Map does not contain the credentialSubject field. No claims can be disclosed.".to_string()); }
            Some(claims) => { claims }
        };

        match claims_value {
            Value::Object(claims) => { Ok(&claims) }
            _ => { Err("CredentialSubject field is not an object".to_string()) }
        }
    }


    /// A function that given either a VC or a VP, and a set of claims, both as Maps, inserts the claims in the map.
    ///
    /// # Arguments
    /// * `map` - VC or VP from which it's necessary to retrieve the claims.
    /// * `claims` - Claims to include in the VC or VP.
    ///
    /// # Returns
    /// Returns a result containing a string representing an error.
    fn insert_claims(map: &mut Map<String, Value>, claims: Map<String, Value>) -> Result<(), String> {
        match map.insert(CLAIMS.to_string(), Value::Object(claims)) {
            None => { Err("Claim set not present. This should never happen.".to_string()) }
            Some(_) => { Ok(()) }
        }
    }


    /// A function that given either a VC or a VP in form of a map, removes the claims included in it.
    ///
    /// # Arguments
    /// * `map` - VC or VP from which it's necessary to remove the claims.
    ///
    /// # Returns
    /// Returns a result containing a string representing an error.
    fn remove_claims(map: &mut Map<String, Value>) -> Result<(), String> {
        match map.remove(CLAIMS) {
            None => { Err("Claim set not present. This should never happen.".to_string()) }
            Some(_) => { Ok(()) }
        }
    }


    /// Filters the VC or VP passed as input to only include the disclosures already present in the disclosure vector.
    ///
    /// # Arguments
    /// * `map` - VC from which it's necessary to filter the claims.
    /// * `disclosures` - A vector of strings that contains the disclosures to be inserted in the VP.
    ///
    /// # Returns
    /// Returns a result containing an array of disclosed indices or a string representing an error.
    fn filter_claims_by_disclosure_and_insert(map: &mut Map<String, Value>, disclosures: &Vec<String>) -> Result<Vec<usize>, String> {

        let claims = Self::extract_claims(map)?;
        let mut disclosed_claims: Map<String, Value> = Map::new();
        let mut disclosed_indices: Vec<usize> = vec![];

        'disclosure_loop: for disclosure in disclosures {
            for (i, (key, value)) in claims.iter().enumerate() {
                if *key == *disclosure {
                    disclosed_claims.insert(key.clone(), value.clone());
                    disclosed_indices.push(i);
                    continue 'disclosure_loop;
                }
            }
        }

        Self::insert_claims(map, disclosed_claims)?;

        Ok(disclosed_indices)
    }


    /// Encodes the claims passed as argument to be a vector of vectors of bytes. Currently only works with Values that are strings.
    ///
    /// # Arguments
    /// * `claims` - A map containing the claims.
    ///
    /// # Returns
    /// Returns a result containing the encoding of claims as bytes or a string representing an error.
    fn convert_claims_to_bytes(claims: &Map<String, Value>) -> Result<Vec<Vec<u8>>, String> {
        let mut messages: Vec<String> = vec![];
        let mut message;

        for (key, value) in claims {
            if let Value::String(val) = value { // Only works with strings
                message = key.clone();
                message.push(':');
                message.push_str(val);
                messages.push(message);
            }
        }

        let byte_messages: Vec<Vec<u8>> = messages.iter().map(|message| {
            message.clone().into_bytes()
        }).collect();

        Ok(byte_messages)
    }


    /// Converts the input argument map to a JwtPayload and a JwsHeader
    ///
    /// # Arguments
    /// * `map` - Either the VC or the VP passed as a map.
    ///
    /// # Returns
    /// Returns the JwsHeader and JwtPayload wrapped in a result or a string containing an errror.
    fn convert_map_to_payload_and_header(map: &Map<String, Value>) -> Result<(JwsHeader, JwtPayload), String> {
        let mut header: JwsHeader = JwsHeader::new();
        header.set_algorithm(Self::ALGORITHM);

        let payload: JwtPayload = match JwtPayload::from_map(map.clone()) {
            Ok(payload) => { payload }
            Err(err) => { return Err(format!("Failed to encode payload from map: [{err}]")); }
        };

        Ok((header, payload))
    }


    /// Encodes the map passed in input as a jwt
    ///
    /// # Arguments
    /// * `map` - A VC or a VP to be encoded as a jwt.
    ///
    /// # Returns
    /// Returns a string containing the encoded jwt or a string containing an error in case of failure.
    fn encode_jwt(map: &Map<String, Value>) -> Result<String, String> {

        let (header, payload) = Self::convert_map_to_payload_and_header(map)?;

        let jwt = match jwt::encode_unsecured(&payload, &header) {
            Ok(jwt) => { jwt }
            Err(err) => { return Err(format!("Failed to encode jwt: [{err}]")); }
        };

        Ok(jwt)
    }


    /// Decodes the input string jwt and returns the payload.
    ///
    /// # Arguments
    /// * `jwt` - The jwt to be decoded.
    ///
    /// # Returns
    /// Returns the map decoded from the jwt.
    fn decode_jwt(jwt: &String) -> Result<Map<String, Value>, String> {
        let (payload, _header) = match jwt::decode_unsecured(&jwt) {
            Ok((vc, header)) => { (vc, header) }
            Err(err) => { return Err(format!("Failed to decode jwt: [{err}]")); }
        };

        Ok(payload.claims_set().clone())
    }


    /// Encodes the map passed in input as a jwt and signs it using the private key passed in input
    ///
    /// # Arguments
    /// * `map` - A VC or a VP to be encoded as a jwt.
    /// * `private_key` - A byte vector containing a ES256 private key
    ///
    /// # Returns
    /// Returns a string containing the encoded and signed jwt or a string containing an error in case of failure.
    fn encode_and_sign_jwt(map: &Map<String, Value>, private_key: &impl AsRef<[u8]>) -> Result<String, String> {

        let (header, payload) = Self::convert_map_to_payload_and_header(map)?;

        let signer = match ES256.signer_from_pem(private_key) {
            Ok(signer) => { signer }
            Err(err) => { return Err(format!("Failed to create signer: [{err}]"));}
        };

        let jwt = match jwt::encode_with_signer(&payload, &header, &signer) {
            Ok(jwt) => { jwt }
            Err(err) => { return Err(format!("Failed to encode and sign jwt: [{err}]")); }
        };

        Ok(jwt)
    }


    /// Decodes and verifies the jwt passed in input and returns the payload.
    ///
    /// # Arguments
    /// * `jwt` - A VC or a VP to be encoded as a jwt.
    /// * `public_key` - A byte array containing the encoding of a public key to verify the encoded jwt.
    ///
    /// # Returns
    /// Returns the decoded and verified payload or a string containing an error in case of failure.
    fn decode_and_verify_jwt(jwt: &String, public_key: &impl AsRef<[u8]>) -> Result<Map<String, Value>, String> {

        let verifier = match ES256.verifier_from_pem(public_key) {
            Ok(verifier) => { verifier }
            Err(err) => { return Err(format!("Failed to create verifier: [{err}]")); }
        };

        let (payload, _header) = match jwt::decode_with_verifier(&jwt, &verifier) {
            Ok(jwt) => { jwt }
            Err(err) => { return Err(format!("Failed to decode and verify jwt: [{err}]")); }
        };

        Ok(payload.claims_set().clone())
    }


    /// Given a VC or a VP, and a field name and value, this function serializes the field name and value and inserts it into the VC or VP.
    ///
    /// # Arguments
    /// * `map` - The VC or VP to manipulate.
    /// * `field` - Name of the element to be serialized and inserted.
    /// * `element` - Value of the element to be serialized and inserted.
    ///
    /// # Returns
    /// Returns a result wrapping a string that displays information about the error in case of failure.
    fn serialize_and_insert<T>(map: &mut Map<String, Value>, field: String, element: &T) -> Result<(), String>
    where
        T: ?Sized + Serialize,
    {
        let serialized_element = match serde_json::to_string(&element) {
            Ok(serialized_element) => { serialized_element }
            Err(err) => { return Err(format!("Failed to serialize {field}: [{err}]")); }
        };

        let encoded_element = multibase::Base::Base64Url.encode(serialized_element);

        map.insert(field.to_string(), Value::String(encoded_element));       // We just ignore if another field was present

        Ok(())
    }

    /// Extracts an element from a VC or VP map and deserializes it into an object.
    ///
    /// # Arguments
    /// * `map` - The VC or VP from which the element must be extracted from.
    /// * `field` - Name of the element to be extracted.
    ///
    /// # Returns
    /// Returns the decoded value of the element or a string containing an error in case of failure.
    fn get_and_decode<T>(map: &Map<String, Value>, field: String) -> Result<T, String>
    where
        T: DeserializeOwned,
    {
        let encoded_element: String = match map.get(&field) {
            None => return Err(format!("Failed to retrieve {field} from {:?}", map)),
            Some(value) => match value {
                Value::String(encoded_element) => { encoded_element.clone() }
                _ => { return Err(format!("Encoded {field} in is not a string")) }
            },
        };

        let serialized_element_byte_vector = match multibase::Base::Base64Url.decode(&encoded_element) {
            Ok(serialized_element) => { serialized_element }
            Err(err) => { return Err(format!("Failed to decode {field} [{err}].")); }
        };

        let serialized_element = match String::from_utf8(serialized_element_byte_vector) {
            Ok(serialized_element) => { serialized_element }
            Err(err) => { return Err(format!("Failed to to convert from byte vector {field}. Failed  [{err}].")); }
        };

        let element: T = match serde_json::from_str::<T>(&serialized_element) {
            Ok(element) => { element }
            Err(err) => { return Err(format!("Failed to deserialize {field} [{err}].")) }
        };

        Ok(element)
    }

}