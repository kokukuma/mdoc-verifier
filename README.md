# mdoc verifier

## Overview

This project is an mdoc (mobile driving license) verification compliant with [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html).

## Included Packages

- `mdoc`: Provides mdoc data model and verification functionality
- `apple_hpke`, `preview_hpke`, `openid4vp`: Offer session encryption capabilities for each protocol
- `server`: Example server demonstrating how to use the verifier

## Prerequisites

This sample server expects an environment capable of using the [Identity Credentials API](https://wicg.github.io/digital-credentials/#protocol-registry).


## How to use sample server
* Prepare a wallet on your device. For details, refer to:
  * [HOWTO: Try the Prototype API in Chrome Android](https://github.com/WICG/digital-credentials/wiki/HOWTO%3A-Try-the-Prototype-API-in-Chrome-Android)

* Install ngrok and set up the authentication token:
```
$ ngrok config add-authtoken (token)

$ ngrok config edit
version: "2"
authtoken: (token)
tunnels:
  fido-server:
    addr: 8080
    proto: http
    subdomain: (server-sub-domain)
  web-client:
    addr: 8081
    proto: http
    subdomain: (client-sub-domain)
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


