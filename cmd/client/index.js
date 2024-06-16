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
    const req = await $.post(
        'https://fido-kokukuma.jp.ngrok.io/getIdentityRequest',
        JSON.stringify({
          protocol: "openid4vp",
        }),
        function (data, status) {
          return data
        },
        'json').fail(function(response) {
            console.log(response);
            alert("failed to get request" + response);
        });
    console.log(req)


    const controller = new AbortController();
    const signal = controller.signal;
    const response = await navigator.identity.get({
        signal: signal,
        digital: {
          providers: [{
            protocol: "openid4vp",
            request: req,
          }],
        }
    });
    console.log(response)

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
        'https://fido-kokukuma.jp.ngrok.io/getIdentityRequest',
        JSON.stringify({
          protocol: "preview",
        }),
        function (data, status) {
          return data
        },
        'json').fail(function(response) {
            console.log(response);
            alert("failed to get request" + response);
        });
    console.log(req)


    const controller = new AbortController();
    const signal = controller.signal;
    const response = await navigator.identity.get({
        signal: signal,
        digital: {
          providers: [{
            protocol: "preview",
            request: req,
          }],
        }
    });
    console.log(response)

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

