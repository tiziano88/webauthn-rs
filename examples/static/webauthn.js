const cose_alg_ECDSA_w_SHA256 = -7;
const cose_alg_ECDSA_w_SHA512 = -36;

function register() {
  fetch("/challenge/xxx", {method: "POST"})
    .then(res => res.json())
    .then(challenge => {
      console.log("challenge");
      console.log(challenge);
      challenge.publicKey.challenge = fromBase64(challenge.publicKey.challenge);
      challenge.publicKey.user.id = fromBase64(challenge.publicKey.user.id);
      return navigator.credentials.create(challenge)
    .then(newCredential => {
      console.log("PublicKeyCredential Created");
      console.log(newCredential);
      console.log(typeof(newCredential));
      const cc = {};
      cc.id = newCredential.id;
      cc.rawId = toBase64(newCredential.rawId);
      cc.response = {};
      cc.response.attestationObject = toBase64(newCredential.response.attestationObject);
      cc.response.clientDataJSON = toBase64(newCredential.response.clientDataJSON);
      cc.type = newCredential.type;
      console.log(cc);
      return fetch("/register", {method: "POST", body: JSON.stringify(cc)})
    })
    .catch(err => console.log(err));
  });
}

function toBase64(data) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(data)))
}

function fromBase64(data) {
  return Uint8Array.from(atob(data), c => c.charCodeAt(0))
}
