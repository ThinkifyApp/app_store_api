use std::collections::HashSet;

use jsonwebtoken::{decode_header, Algorithm, DecodingKey, Validation};
use openssl::x509::X509;
use serde::{Deserialize, Serialize};

use crate::APPLE_CERT;

fn decode_payload_cert(jwt_payload: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let Ok(header) = decode_header(jwt_payload) else {
        return Err("failed to decode header".into());
    };

    let headers = header.x5c_der().unwrap().unwrap();
    let certs: Vec<_> = headers.iter().map(|h| X509::from_der(h).unwrap()).collect();

    for i in 0..3 {
        if i == 2 {
            certs[i]
                .verify(&APPLE_CERT.get().unwrap().public_key().unwrap())
                .unwrap();
        } else {
            certs[i]
                .verify(&certs[i + 1].public_key().unwrap())
                .unwrap();
        }
    }

    let leaf_pubkey = certs[0].public_key().unwrap();

    let pub_key = leaf_pubkey.public_key_to_der().unwrap();
    let pub_key = &pub_key[pub_key.len() - 65..];
    Ok(pub_key.to_vec())
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignedResponseV2 {
    #[serde(rename = "signedPayload")]
    pub signed_payload: String,
}

impl SignedResponseV2 {
    pub fn decode(&self) -> DecodedResponseV2 {
        let key = decode_payload_cert(&self.signed_payload).unwrap();
        let mut val = Validation::new(Algorithm::ES256);
        val.required_spec_claims = HashSet::new();

        jsonwebtoken::decode::<DecodedResponseV2>(
            &self.signed_payload,
            &DecodingKey::from_ec_der(&key),
            &val,
        )
        .unwrap()
        .claims
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DecodedResponseV2 {
    #[serde(rename = "notificationUUID")]
    pub notification_uuid: String,
    pub subtype: Option<String>,
    pub notification_type: String,
    pub data: Option<DecodedData>,
    pub version: String,
    pub signed_date: i64,
    pub summary: Option<DecodedSummary>,
}

// #[derive(Serialize, Deserialize, Debug)]
// pub struct SignedData {
//     #[serde(rename = "signedPayload")]
//     pub signed_payload: String,
// }
//
// impl SignedData {
//     pub fn decode(&self) -> DecodedData {
//         let key = decode_payload_cert(&self.signed_payload).unwrap();
//         let mut val = Validation::new(Algorithm::ES256);
//         val.required_spec_claims = HashSet::new();
//
//         jsonwebtoken::decode::<DecodedData>(
//             &self.signed_payload,
//             &DecodingKey::from_ec_der(&key),
//             &val,
//         )
//         .unwrap()
//         .claims
//     }
// }

#[derive(Serialize, Deserialize, Debug)]
pub struct SignedSummary {
    #[serde(rename = "signedPayload")]
    pub signed_payload: String,
}

impl SignedSummary {
    pub fn decode(&self) -> DecodedSummary {
        let key = decode_payload_cert(&self.signed_payload).unwrap();
        let mut val = Validation::new(Algorithm::ES256);
        val.required_spec_claims = HashSet::new();

        jsonwebtoken::decode::<DecodedSummary>(
            &self.signed_payload,
            &DecodingKey::from_ec_der(&key),
            &val,
        )
        .unwrap()
        .claims
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DecodedData {
    pub app_apple_id: Option<i64>,
    pub bundle_id: String,
    pub bundle_version: Option<String>,
    pub consumption_request_reason: Option<String>,
    pub environment: String,
    pub signed_renewal_info: Option<String>,
    pub signed_transaction_info: Option<String>,
    pub status: Option<i32>,
}

impl DecodedData {
    pub fn decode_transaction_info(
        &self,
    ) -> Result<DecodedTransaction, Box<dyn std::error::Error>> {
        let trans_info = self.signed_transaction_info.as_ref().unwrap();
        let key = decode_payload_cert(trans_info).unwrap();
        let mut val = Validation::new(Algorithm::ES256);
        val.required_spec_claims = HashSet::new();

        Ok(jsonwebtoken::decode::<DecodedTransaction>(
            trans_info,
            &DecodingKey::from_ec_der(&key),
            &val,
        )
        .map(|i| i.claims)?)
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DecodedSummary {
    pub app_apple_id: i64,
    pub bundle_id: String,
    pub environment: String,
    pub request_identifier: String,
    pub product_id: String,
    pub storefront_country_codes: Vec<String>,
    pub failed_count: i64,
    pub succeeded_count: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPayloadExternalPurchaseToken {
    pub external_purchase_id: String,
    pub token_creation_date: i64,
    pub app_apple_id: i64,
    pub bundle_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignedTransaction {
    #[serde(rename = "signedTransactionInfo")]
    pub signed_transaction_info: String,
}

impl SignedTransaction {
    pub fn decode(&self) -> DecodedTransaction {
        let key = decode_payload_cert(&self.signed_transaction_info).unwrap();
        let mut val = Validation::new(Algorithm::ES256);
        val.required_spec_claims = HashSet::new();

        jsonwebtoken::decode::<DecodedTransaction>(
            &self.signed_transaction_info,
            &DecodingKey::from_ec_der(&key),
            &val,
        )
        .unwrap()
        .claims
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DecodedTransaction {
    #[serde(rename = "transactionId")]
    pub transaction_id: String,

    #[serde(rename = "originalTransactionId")]
    pub original_transaction_id: String,

    #[serde(rename = "webOrderLineItemId")]
    pub web_order_line_item_id: String,

    #[serde(rename = "bundleId")]
    pub bundle_id: String,

    #[serde(rename = "productId")]
    pub product_id: String,

    #[serde(rename = "subscriptionGroupIdentifier")]
    pub subscription_group_identifier: String,

    #[serde(rename = "purchaseDate")]
    pub purchase_date: i64,

    #[serde(rename = "originalPurchaseDate")]
    pub original_purchase_date: i64,

    #[serde(rename = "expiresDate")]
    pub expires_date: i64,

    #[serde(rename = "quantity")]
    pub quantity: i64,

    #[serde(rename = "type")]
    pub welcome7_type: String,

    #[serde(rename = "appAccountToken")]
    pub app_account_token: String,

    #[serde(rename = "inAppOwnershipType")]
    pub in_app_ownership_type: String,

    #[serde(rename = "signedDate")]
    pub signed_date: i64,

    #[serde(rename = "environment")]
    pub environment: String,

    #[serde(rename = "transactionReason")]
    pub transaction_reason: String,

    #[serde(rename = "storefront")]
    pub storefront: String,

    #[serde(rename = "storefrontId")]
    pub storefront_id: String,

    #[serde(rename = "price")]
    pub price: i64,

    #[serde(rename = "currency")]
    pub currency: String,
}
