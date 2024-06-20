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
        'json').fail(function(err) {
            console.log(err);
            alert("failed to get request" + err);
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
        'https://fido-kokukuma.jp.ngrok.io/verifyIdentityResponse',
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
            alert("failed to verify response: "+ err);
        });
    console.log(verifyResult)

  } catch (error) {
    console.log(error)
    alert(error)
  }
}

async function getIdentity() {
  try {
    const req = await $.post(
        'https://fido-kokukuma.jp.ngrok.io/getIdentityRequest',
        JSON.stringify({
          protocol: "preview",
        }),
        function (data, status) {
          return data
        },
        'json').fail(function(err) {
            console.log(err);
            alert("failed to get request" + err);
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
        'https://fido-kokukuma.jp.ngrok.io/verifyIdentityResponse',
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
            alert("failed to verify response: "+ err);
        });
    console.log(verifyResult)

  } catch (error) {
    console.log(error)
    alert(error)
  }
}

