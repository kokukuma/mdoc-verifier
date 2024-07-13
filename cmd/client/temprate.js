async function getIdentityWithOpenid4VP() {
  try {
    const req = await $.post(
        "https://{{.ServerDomain}}/getIdentityRequest",
        JSON.stringify({
          protocol: "openid4vp",
        }),
        function (data, status) {
          return data
        },
        'json').fail(function(err) {
            console.log(err);
            alert("failed to get request: "+ JSON.stringify(err));
        });
    console.log(req)
    console.log(req.data)

    const controller = new AbortController();
    const signal = controller.signal;

    // https://wicg.github.io/digital-credentials/
    const response = await navigator.identity.get({
        signal: signal,
        digital: {
          providers: [{
            protocol: "openid4vp",
            request: req.data,
          }],
        }
    });
    console.log(response)

    const verifyResult = await $.post(
        "https://{{.ServerDomain}}/verifyIdentityResponse",
        JSON.stringify({
          session_id: req.session_id,
          protocol: response.protocol,
          data: response.data,
          origin: location.origin,
        }),
        function (data, status) {
          alert(JSON.stringify(data));
        },
        'json').fail(function(err) {
            console.log(err);
            alert("failed to verify response: "+ JSON.stringify(err.responseJSON.Error));
        });
    console.log(verifyResult)

  } catch (error) {
    console.log(error)
    alert(error)
  }
}

async function getIdentifyFromEUDIW() {
  window.location.href = "eudi-openid4vp://verifier-backend.eudiw.dev?client_id=fido-kokukuma.jp.ngrok.io&request_uri=https%3A%2F%2Ffido-kokukuma.jp.ngrok.io%2Fwallet%2Frequest.jwt"

  // ok
  // window.location.href = "eudi-openid4vp://verifier-backend.eudiw.dev?client_id=fido-kokukuma.jp.ngrok.io&request_uri=https%3A%2F%2Fverifier-backend.eudiw.dev%2Fwallet%2Fdirect_post"

  // ok
  // window.location.href = "eudi-openid4vp://verifier-backend.eudiw.dev?client_id=verifier-backend.eudiw.dev&request_uri=https%3A%2F%2Fverifier-backend.eudiw.dev%2Fwallet%2Fdirect_post"
}

async function getIdentity() {
  try {
    const req = await $.post(
        "https://{{.ServerDomain}}/getIdentityRequest",
        JSON.stringify({
          protocol: "preview",
        }),
        function (data, status) {
          return data
        },
        'json').fail(function(err) {
            console.log(err);
            alert("failed to get request: "+ JSON.stringify(err));
        });
    console.log(req)
    console.log(req.data)


    const controller = new AbortController();
    const signal = controller.signal;

    // https://wicg.github.io/digital-credentials/
    const response = await navigator.identity.get({
        signal: signal,
        digital: {
          providers: [{
            protocol: "preview",
            request: req.data,
          }],
        }
    });
    console.log(response)

    const verifyResult = await $.post(
        "https://{{.ServerDomain}}/verifyIdentityResponse",
        JSON.stringify({
          session_id: req.session_id,
          protocol: response.protocol,
          data: response.data,
          origin: location.origin,
        }),
        function (data, status) {
          alert(JSON.stringify(data));
        },
        'json').fail(function(err) {
            console.log(err);
            alert("failed to verify response: "+ JSON.stringify(err.responseJSON.Error));
        });
    console.log(verifyResult)

  } catch (error) {
    console.log(error)
    alert(error)
  }
}

