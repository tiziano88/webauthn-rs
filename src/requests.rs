use byteorder::ByteOrder;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub id: String,
    pub raw_id: String,
    pub response: CredentialsResponse,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialsResponse {
    pub attestation_object: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientData {
    #[serde(rename = "type")]
    pub type_: String,
    pub challenge: String,
    pub origin: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attestation<'a> {
    pub fmt: String,
    //#[serde(with = "serde_bytes")]
    pub auth_data: &'a [u8],
}

#[derive(Debug)]
pub struct DecodedAuthData {
    pub rpid_hash: Vec<u8>,
    pub user_present: bool,
    pub user_verified: bool,
    pub attested_credential_data_included: bool,
    pub extension_data_included: bool,
    pub counter: u32,
    pub attested_credential_data: AttestedCredentialData,
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
pub struct AttestedCredentialData {
    pub aaguid: Vec<u8>,
    pub credentialid_length: u16,
    pub credentialid: Vec<u8>,
    //credential_public_key: PublicKey,
}

#[derive(Debug, Deserialize)]
pub struct PublicKey {
    #[serde(rename = "1")]
    pub key_type: u8,
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
            // See https://w3c.github.io/webauthn/#sctn-encoded-credPubKey-examples
            //credential_public_key: serde_cbor::from_slice(public_key_cbor)
            //.expect("could not decode public key"),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub response: AuthenticatorAssertionResponse,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorAssertionResponse {
    pub authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub signature: String,
}
