use serde_json::{Map, Value};
use crate::common_data::CommonData;
use crate::adapters::adapter::Adapter;
use crate::sd_algorithms::monoclaim::monoclaim::MonoClaimInstance;
use crate::sd_algorithms::sd_algorithm::SdAlgorithm;

pub struct MonoClaimAdapter {
    holder_public_key: Vec<u8>,
    holder_private_key: Vec<u8>,
    issuer_public_key: Vec<u8>,
    issuer_private_key: Vec<u8>,
}

impl Adapter for MonoClaimAdapter {
    fn sd_algorithm(&self) -> String {
        MonoClaimInstance::ALGORITHM.to_string()
    }

    fn new(_claims_len: usize) -> Result<Self, String> {
        let (holder_public_key, holder_private_key) = CommonData::holder_keys()?;
        let (issuer_public_key, issuer_private_key) = CommonData::issuer_keys()?;

        Ok(MonoClaimAdapter {
            holder_public_key,
            holder_private_key,
            issuer_public_key,
            issuer_private_key,
        })
    }

    fn issue_vc(&self, raw_vc: &Map<String, Value>) -> Result<(Map<String, Value>, String), String> {
        MonoClaimInstance::issue_vc(raw_vc, &self.issuer_private_key)
    }

    fn verify_vc(&self, vc: &Map<String, Value>) -> Result<(), String> {
        MonoClaimInstance::verify_vc(vc, &self.issuer_public_key)
    }

    fn issue_vp(&self, vc: &Map<String, Value>, disclosures: &Vec<String>) -> Result<(Map<String, Value>, String), String> {
        MonoClaimInstance::issue_vp(vc, disclosures, &self.holder_private_key)
    }

    fn verify_vp(&self, vp_jwt: &String) -> Result<(), String> {
        MonoClaimInstance::verify_vp(vp_jwt, &self.issuer_public_key, &self.holder_public_key)
    }

    fn issuer_keypair(&self) -> Result<(String, String), String> {
        let issuer_public_key = match serde_json::to_string(&self.issuer_public_key) {
            Ok(ipk) => {ipk}
            Err(err) => { return Err(format!("Error in serializing issuer public key: [{err}]")) }
        };
        let issuer_private_key = match serde_json::to_string(&self.issuer_private_key) {
            Ok(ipk) => {ipk}
            Err(err) => { return Err(format!("Error in serializing issuer private key: [{err}]")) }
        };

        Ok((issuer_public_key, issuer_private_key))
    }
}