function base64UrlDecode(input) {
    // パディングを追加
    input = input
        .replace(/-/g, '+') // URLで使用可能な文字を元に戻す
        .replace(/_/g, '/'); // URLで使用可能な文字を元に戻す

    switch (input.length % 4) {
        case 2:
            input += '==';
            break;
        case 3:
            input += '=';
            break;
    }

    return atob(input); // 標準のBase64デコード
}

function base64UrlEncode(input) {
    let base64 = btoa(input); // 標準のBase64エンコード
    return base64
        .replace(/\+/g, '-') // URLで使用可能な文字に置き換え
        .replace(/\//g, '_') // URLで使用可能な文字に置き換え
        .replace(/=+$/, ''); // パディングを削除
}

// Base64 to ArrayBuffer
function bufferDecode(value) {
  console.log(value)
  return Uint8Array.from(base64UrlDecode(value), c => c.charCodeAt(0));
}

// ArrayBuffer to URLBase64
function bufferEncode(value) {
  // return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
  //   .replace(/\+/g, "-")
  //   .replace(/\//g, "_")
  //   .replace(/=/g, "");
  return base64UrlEncode(String.fromCharCode.apply(null, new Uint8Array(value)));
}

async function getIdentityWithOpenid4VP() {
  try {
    const controller = new AbortController();
    const signal = controller.signal;
    const response = await navigator.identity.get({
        signal: signal,
        digital: {
          providers: [{
            protocol: "openid4vp",
            request: JSON.stringify({
              client_id: "digital-credentials.dev",
              client_id_scheme: "web-origin",
              resopnse_type: "vp_token",
              nonce: "dIMeIndW3K81jFV7PKbdDcusanByIfMB9DBPo8Wu1i4=",
              presentation_definition: {
                id: "mDL-request-demo",
                input_descriptors: [{
                  id: "org.iso.18013.5.1.mDL",
                  format: {
                    mso_mdoc: {
                      alg: ["ES256"]
                    }
                  },
                  constraints: {
                    limit_disclosure: "required",
                    fields: [
                      {
                        path: ["$['org.iso.18013.5.1']['family_name']"],
                        intent_to_retain: false
                      },
                      {
                        path: ["$['org.iso.18013.5.1']['given_name']"],
                        intent_to_retain: false
                      },
                      {
                        path: ["$['org.iso.18013.5.1']['age_over_21']"],
                        intent_to_retain: false
                      }
                    ]
                  }
                }]
              }
            })
          }],
        }
    });
    console.log(response)
    console.log(response.protocol)
    console.log(response.data)

    // console.log(base64UrlDecode(response.data))

    // echo $(response.data) | base64 -D | cbor export --format=json
    // alert(response.data)

    const result = await $.post(
        'https://fido-kokukuma.jp.ngrok.io/verifyResponse',
        JSON.stringify({
          protocol: response.protocol,
          data: response.data,
          origin: location.origin,
        }),
        function (data, status) {
          alert(JSON.stringify(data));
        },
        'json').fail(function(response) {
            console.log(response);
            alert("register/finish returns error");
        });
    console.log(result)

  } catch (error) {
    console.log(error)
    alert(error)
  }
}

async function getIdentity() {
  // Gets a CBOR with specific fields out of mobile driver's license as an mdoc
  try {
    const req = await $.post(
        'https://fido-kokukuma.jp.ngrok.io/getRequest',
        JSON.stringify({
          protocol: "preview",
        }),
        function (data, status) {
          return data
        },
        'json').fail(function(response) {
            console.log(response);
            alert("register/finish returns error");
        });
    console.log(req)


    const controller = new AbortController();
    const signal = controller.signal;
    const response = await navigator.identity.get({
        signal: signal,
        digital: {
          providers: [{
            // protocol: "basic",
            protocol: "preview",
            request: JSON.stringify({
              selector: {
                format: ["mdoc"],
                retention: {days: 90},
                doctype: "org.iso.18013.5.1.mDL",
                fields: [
                  {
                    namespace: "org.iso.18013.5.1",
                    name: "family_name",
                    intentToRetain: false
                  },
                  {
                    namespace: "org.iso.18013.5.1",
                    name: "given_name",
                    intentToRetain: false
                  },
                  {
                    namespace: "org.iso.18013.5.1",
                    name: "age_over_21",
                    intentToRetain: false
                  },
                  {
                    namespace: "org.iso.18013.5.1",
                    name: "document_number",
                    intentToRetain: false
                  },
                  {
                    namespace: "org.iso.18013.5.1",
                    name: "portrait",
                    intentToRetain: false
                  },
                  {
                    namespace: "org.iso.18013.5.1",
                    name: "driving_privileges",
                    intentToRetain: false
                  },
                ],
              },
              nonce: req.nonce,
              readerPublicKey: req.public_key,
            })
          }],
        }
    });
    console.log(response)
    console.log(response.protocol)
    console.log(response.data)
    // verify and get information from
    // * protocol: response.protocol
    // * data: response.data
    // * sate: request['state'] -> nonce, private_key, public_key
    // * origin: location.origin

    const result = await $.post(
        'https://fido-kokukuma.jp.ngrok.io/verifyResponse',
        JSON.stringify({
          protocol: response.protocol,
          data: response.data,
          origin: location.origin,
        }),
        function (data, status) {
          alert(JSON.stringify(data));
        },
        'json').fail(function(response) {
            console.log(response);
            alert("register/finish returns error");
        });
    console.log(result)

  } catch (error) {
    console.log(error)
    alert(error)
  }
}

