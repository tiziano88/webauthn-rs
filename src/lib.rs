#[macro_use]
extern crate serde_derive;
extern crate base64;
#[macro_use]
extern crate log;
extern crate byteorder;
extern crate sha2;

use sha2::Digest;

mod challenge;
pub mod requests;

const CHALLENGE_SIZE_BYTES: usize = 32;

type UserId = String;

#[derive(Debug, Clone)]
pub struct Credential {
    pub id: String,
}

#[derive(Debug)]
pub struct WebAuthn {
    relying_party: String,
    challenges: std::collections::HashMap<UserId, challenge::Challenge>,
    credentials: std::collections::HashMap<UserId, Vec<Credential>>,
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
    pub fn generate_challenge(&mut self, user_id: UserId) -> challenge::Challenge {
        let challenge = challenge::Challenge::new(CHALLENGE_SIZE_BYTES);
        self.challenges.insert(user_id, challenge.clone());
        challenge
    }

    pub fn get_credentials(&self, user_id: UserId) -> Vec<Credential> {
        self.credentials.get(&user_id).unwrap_or(&vec![]).to_vec()
    }

    pub fn register(&mut self, req: &requests::RegisterRequest) -> bool {
        info!("req: {:?}", req);
        let decoded_client_data_json_vec =
            base64::decode(&req.response.client_data_json).expect("could not convert client data");
        let client_data: requests::ClientData =
            serde_json::from_slice(&decoded_client_data_json_vec)
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
        let attestation: requests::Attestation = serde_cbor::from_slice(&attestation_object_vec)
            .expect("coluld not parse attestation object");
        info!("attestation: {:?}", attestation);
        let decoded_auth_data: requests::DecodedAuthData = attestation.auth_data.into();
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
    pub fn verify(&mut self, req: &requests::LoginRequest) -> bool {
        info!("login request: {:?}", req);
        let decoded_client_data_json_vec =
            base64::decode(&req.response.client_data_json).expect("could not convert client data");
        let client_data: requests::ClientData =
            serde_json::from_slice(&decoded_client_data_json_vec)
                .expect("could not parse client data");
        info!("client data: {:?}", client_data);
        false
    }
}
