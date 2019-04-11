# WebAuthn

*WARNING*: This crate is experimental and *not ready for production use*; it
does not currently implement any of the necessary crypto and does not provide
any authentication guarantees.

The webauthn crate provides [Rocket](https://rocket.rs/) handlers to implement a
[Relying Party](https://www.w3.org/TR/webauthn/#webauthn-relying-party)
supporting passwordless or two-factor authentication using security keys
according to the [Web Authentication](https://www.w3.org/TR/webauthn/)
specification.
