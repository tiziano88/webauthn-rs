#[macro_use]
extern crate serde_derive;
extern crate base64;
#[macro_use]
extern crate log;
extern crate byteorder;
extern crate sha2;

use byteorder::ByteOrder;
use sha2::Digest;

mod challenge;

const CHALLENGE_SIZE_BYTES: usize = 32;

#[derive(Debug, Clone)]
pub struct Credential {
    pub id: String,
}

#[derive(Debug)]
pub struct WebAuthn {
    relying_party: String,
    challenges: std::collections::HashMap<String, challenge::Challenge>,
    credentials: std::collections::HashMap<String, Vec<Credential>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    id: String,
    raw_id: String,
    response: CredentialsResponse,
    #[serde(rename = "type")]
    type_: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialsResponse {
    attestation_object: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientData {
    #[serde(rename = "type")]
    type_: String,
    challenge: String,
    origin: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attestation<'a> {
    fmt: String,
    //#[serde(with = "serde_bytes")]
    auth_data: &'a [u8],
}

#[derive(Debug)]
pub struct DecodedAuthData {
    rpid_hash: Vec<u8>,
    user_present: bool,
    user_verified: bool,
    attested_credential_data_included: bool,
    extension_data_included: bool,
    counter: u32,
    attested_credential_data: AttestedCredentialData,
}

impl From<&[u8]> for DecodedAuthData {
    fn from(v: &[u8]) -> Self {
        let flags = v[32];
        DecodedAuthData {
            rpid_hash: v[0..32].into(),
            user_present: (flags & (1 << 0)) != 0,
            user_verified: (flags & (1 << 2)) != 0,
            attested_credential_data_included: (flags & (1 << 6)) != 0,
            extension_data_included: (flags & (1 << 7)) != 0,
            counter: byteorder::BigEndian::read_u32(&v[33..37]),
            attested_credential_data: v[37..].into(),
        }
    }
}

#[derive(Debug)]
struct AttestedCredentialData {
    aaguid: Vec<u8>,
    credentialid_length: u16,
    credentialid: Vec<u8>,
    //credential_public_key: PublicKey,
}

#[derive(Debug, Deserialize)]
struct PublicKey {
    #[serde(rename = "1")]
    key_type: u8,
    //#[serde(rename = "2")]
    //type_: u8,
    //#[serde(rename = "crv")]
    //curve: u8,
}

impl From<&[u8]> for AttestedCredentialData {
    // See:
    // - https://w3c.github.io/webauthn/#sec-attested-credential-data
    // - https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAssertionResponse/authenticatorData
    fn from(v: &[u8]) -> Self {
        let credentialid_length = byteorder::BigEndian::read_u16(&v[16..18]);
        let public_key_cbor = &v[18 + credentialid_length as usize..];
        info!("public key cbor: {:?}", public_key_cbor);
        AttestedCredentialData {
            aaguid: v[0..16].into(),
            credentialid_length: credentialid_length,
            credentialid: v[18..18 + credentialid_length as usize].into(),
            //credential_public_key: serde_cbor::from_slice(public_key_cbor)
            //.expect("could not decode public key"),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    response: AuthenticatorAssertionResponse,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorAssertionResponse {
    authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    signature: String,
}

impl WebAuthn {
    pub fn new(relying_party: String) -> Self {
        WebAuthn {
            relying_party: relying_party,
            challenges: std::collections::HashMap::new(),
            credentials: std::collections::HashMap::new(),
        }
    }

    pub fn relying_party(&self) -> String {
        self.relying_party.clone()
    }

    // See https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API
    // https://w3c.github.io/webauthn/#registering-a-new-credential
    pub fn generate_challenge(&mut self, username: String) -> challenge::Challenge {
        let challenge = challenge::Challenge::new(CHALLENGE_SIZE_BYTES);
        self.challenges.insert(username, challenge.clone());
        challenge
    }

    pub fn get_credentials(&self, username: String) -> Vec<Credential> {
        self.credentials.get(&username).unwrap_or(&vec![]).to_vec()
    }

    pub fn register(&mut self, req: &RegisterRequest) -> bool {
        info!("req: {:?}", req);
        let decoded_client_data_json_vec =
            base64::decode(&req.response.client_data_json).expect("could not convert client data");
        let client_data: ClientData = serde_json::from_slice(&decoded_client_data_json_vec)
            .expect("could not parse client data");
        info!("parsed client data: {:?}", client_data);
        // See https://w3c.github.io/webauthn/#registering-a-new-credential.
        if client_data.type_ != "webauthn.create" {
            return false;
        }
        if client_data.challenge != "xx" {
            //return false;
        }
        if client_data.origin != "ll" {
            //return false;
        }
        let mut hasher = sha2::Sha256::new();
        hasher.input(&decoded_client_data_json_vec);
        let hash = hasher.result();
        info!("hash: {:?}", hash);

        let attestation_object_vec = base64::decode(&req.response.attestation_object)
            .expect("could not decode attestation object");
        let attestation: Attestation = serde_cbor::from_slice(&attestation_object_vec)
            .expect("coluld not parse attestation object");
        info!("attestation: {:?}", attestation);
        let decoded_auth_data: DecodedAuthData = attestation.auth_data.into();
        info!("auth_data: {:?}", decoded_auth_data);
        self.credentials.insert(
            "xxx".to_string(),
            vec![Credential {
                id: req.raw_id.clone(),
            }],
        );
        true
    }

    // See:
    // - https://w3c.github.io/webauthn/#verifying-assertion
    pub fn verify(&mut self, req: &LoginRequest) -> bool {
        info!("login request: {:?}", req);
        let decoded_client_data_json_vec =
            base64::decode(&req.response.client_data_json).expect("could not convert client data");
        let client_data: ClientData = serde_json::from_slice(&decoded_client_data_json_vec)
            .expect("could not parse client data");
        info!("client data: {:?}", client_data);
        false
    }
}
