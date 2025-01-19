# mdoc verifier

## Overview

This project is an mdoc/mDL (mobile driving license) verification compliant with [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html).

![mdog](https://github.com/user-attachments/assets/c7a023ae-543d-402a-941f-1ece0030d7c9)

## Included Packages

* `decoder`: Provides decryption functionality for each protocol and parse to mdocResponse
    * `apple_hpke`:  Decryption for Apple's Verify with Wallet API
    * `android_hpke`: Decryption for Android's Identity Credential API (Preview)
    * `openid4vp`: Decryption for OpenID4VP based Identity Credential API
* `session_transcript`: Provides session transcript functionality for each protocol
    * `apple`: Session transcript for Apple's Verify with Wallet API
    * `android`: Session transcript for Android's Identity Credential API (Preview)
    * `openid4vp`: Session transcript for OpenID4VP based Identity Credential API
    * `browser`: Session transcript for browser's Identity Credential API
* `document`: Define the element identifiers for each doctype and namespace.
* `internal`: Contains internal packages
    * `cryptoroot`: Provides certificate management
    * `server`: Contains the code for the sample server
* `mdoc`: Provides mdoc data model and verification functionality

## How to use for Apple's Verify with Wallet API
- See [cmd/script/main.go](https://github.com/kokukuma/mdoc-verifier/blob/master/cmd/script/main.go)
- The apple's sample data can be downlowed from https://developer.apple.com/wallet/get-started-with-verify-with-wallet/

## Status of behavior check
|                                          | owf wallet<br>(prevew)                                             | owf wallet<br>(oid4vp)                                             | Apple wallet<br>(sample data)                                                              | Apple wallet<br>(iOS simulator)                                                                   | EUDI wallet                                                                                                  | 
| ---------------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ | 
| Interface for communicating with wallets | Identity Credential API                                            | Identity Credential API                                            | Verify with Wallet API                                                                     | Verify with Wallet API                                                                            | OID4VP                                                                                                       | 
| Encryption                               | HPKE                                                               | No encryption                                                      | HPKE                                                                                       | HPKE                                                                                              | JOSE                                                                                                         | 
| Reader authenticator                     | -                                                                  | -                                                                  | Verify with the Marchant Key is managed by developer center.<br>(The sample data is fixed) | Verify with the Marchant Key is managed by developer center.<br>(iOS simulator returns mock data) | client_id_schema = x509_san_dns<br><br>(Create root certification and embeded in the wallet)                   | 
| Verification of issuer certification     | ok | ok | Can be verified by trusting the certificate of the issuer attached to the sample.          | The mock data was broken.                                                                         | Unknown where issuer's certificate or root certificate is located.<br><br>Also, the certificate has expired. | 
| Verification of mso                      | ok                                                                 | ok                                                                 | ok                                                                                         | ok                                                                                                | ok                                                                                                           | 
| Verification of device signature         | ok                                                                 | ok                                                                 | ok                                                                                         | The mock data was broken.                                                                         | ok                                                                                                           | 
| Check digest                             | ok                                                                 | ok                                                                 | ok                                                                                         | ok                                                                                                | ok                                                                                                           | 

[original sheet](https://docs.google.com/spreadsheets/d/1dV_0TyqWEhWRaFCl_R4JFSsdgu6CnJZPryuAQfr_rHI/edit?gid=0#gid=0)

## Prerequisites
### Identity Credentials API
* This sample server expects an environment capable of using the [Identity Credentials API](https://wicg.github.io/digital-credentials/#protocol-registry).
* The way of the preparation is described in [HOWTO: Try the Prototype API in Chrome Android](https://github.com/WICG/digital-credentials/wiki/HOWTO%3A-Try-the-Prototype-API-in-Chrome-Android) 

### Open wallet Foundation
* Clone, build and install the `appholder` from [openwallet-foundation-labs/identity-credential](https://github.com/openwallet-foundation-labs/identity-credential)

### Apple Wallet (client app)
* Run the app on the iOS simulator [kokukuma/TestWalletAPI](https://github.com/kokukuma/TestWalletAPI)

### EUDI Wallet - Android
* Clone this repository; [eu-digital-identity-wallet/eudi-app-android-wallet-ui](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui)
* copy root certificate to the wallet
```
cp ${this repository}/internal/cryptoroot/pem/rootCert.pem ${eudi-app-android-wallet-ui}/resporesources-logic/src/main/res/raw/eudi_pid_issuer_ut.pem
```
* Build and install the app.


## How to use sample server
* Install ngrok and set up the authentication token:
```
$ ngrok config add-authtoken (token)

$ ngrok config edit
version: "2"
authtoken: (token)
tunnels:
  id-server:
    addr: 8080
    proto: http
    subdomain: (server-sub-domain)
  web-client:
    addr: 8081
    proto: http
    subdomain: (client-sub-domain)
```
* Environment
```
export SERVER_DOMAIN="(server-sub-domain)"
export CLIENT_DOMAIN="(client-sub-domain)"
```

* Launch ngrok on your laptop
```
make ngrok
```

* Start the server
```
make run
```

* access to the (client-sub-domain)

## links
* [Apple: Verifying Wallet identity requests](https://developer.apple.com/documentation/passkit_apple_pay_and_wallet/wallet/verifying_wallet_identity_requests)
* [EUDIW Architecture and Reference Framework](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/blob/main/docs/arf.md)
* [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
* [The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR)](https://www.rfc-editor.org/rfc/rfc9101.html)
* [JWT Secured Authorization Response Mode for OAuth 2.0 (JARM)](https://openid.net/specs/oauth-v2-jarm-final.html)
