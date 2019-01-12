#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate serde_derive;
extern crate rocket_contrib;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate webauthn;

use rocket::response::NamedFile;
use rocket_contrib::json::Json;
use std::sync::Mutex;
use webauthn::*;

#[get("/")]
pub fn index() -> std::io::Result<NamedFile> {
    NamedFile::open("examples/static/index.html")
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponse {
    public_key: PublicKey,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowCredentials {
    #[serde(rename = "type")]
    type_: String,
    id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKey {
    challenge: String,
    rp: RelyingParty,
    user: User,
    pub_key_cred_params: Vec<PubKeyCredParams>,
    allow_credentials: Vec<AllowCredentials>,
}

#[derive(Debug, Serialize)]
pub struct RelyingParty {
    name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    id: String,
    name: String,
    display_name: String,
}

#[derive(Debug, Serialize)]
pub struct PubKeyCredParams {
    #[serde(rename = "type")]
    type_: String,
    alg: i8,
}

#[post("/challenge/<username>")]
pub fn challenge(w: rocket::State<Mutex<WebAuthn>>, username: String) -> Json<ChallengeResponse> {
    let mut w = w.lock().expect("could not lock state");
    let challenge = w.generate_challenge(username.clone());
    let credentials = w.get_credentials(username.clone());
    debug!("challenge: {} -> {}", username, challenge);
    Json(ChallengeResponse {
        public_key: PublicKey {
            challenge: challenge.to_string(),
            rp: RelyingParty {
                name: w.relying_party(),
            },
            user: User {
                id: username.clone(),
                name: username.clone(),
                display_name: username.clone(),
            },
            pub_key_cred_params: vec![PubKeyCredParams {
                type_: "public-key".to_string(),
                alg: -7,
            }],
            allow_credentials: credentials
                .iter()
                .map(|c| AllowCredentials {
                    type_: "public-key".to_string(),
                    id: c.id.clone(),
                })
                .collect(),
        },
    })
}

#[post("/register", data = "<data>")]
pub fn register(w: rocket::State<Mutex<WebAuthn>>, data: Json<RegisterRequest>) -> String {
    debug!("register: {:?}", *data);
    let mut w = w.lock().expect("could not lock state");
    w.register(&*data);
    "xx".to_string()
}

#[post("/login", data = "<data>")]
pub fn login(w: rocket::State<Mutex<WebAuthn>>, data: Json<LoginRequest>) -> String {
    debug!("login: {:?}", *data);
    let mut w = w.lock().expect("could not lock state");
    w.verify(&*data);
    "xx".to_string()
}

#[get("/js/webauthn.js")]
pub fn webauthn_js() -> std::io::Result<NamedFile> {
    NamedFile::open("examples/static/webauthn.js")
}

fn main() {
    env_logger::init();
    rocket::ignite()
        .mount("/", routes![index, webauthn_js, challenge, register, login])
        .manage(Mutex::new(WebAuthn::new("rprprp".to_string())))
        .launch();
}
