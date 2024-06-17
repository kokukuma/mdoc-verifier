# Identity Credential API Demo

## links
* [HOWTO: Try the Prototype API in Chrome Android](https://github.com/WICG/digital-credentials/wiki/HOWTO%3A-Try-the-Prototype-API-in-Chrome-Android)
* [Digital Credentials](https://wicg.github.io/digital-credentials/#protocol-registry)



## ngrok settings
```
$ ngrok config add-authtoken (token)

$ ngrok config edit
version: "2"
authtoken: (token)
tunnels:
  fido-server:
    addr: 8080
    proto: http
    subdomain: fido-kokukuma
  web-client:
    addr: 8081
    proto: http
    subdomain: client-kokukuma
```
