

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
    const response = await navigator.credentials.get({
        digital: {
          providers: [
            {
              protocol: "openid4vp",
              request: req.data,
            }
          ]
        },
    })
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
    alert(JSON.stringify(error));
  }
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
    const response = await navigator.credentials.get({
        digital: {
          providers: [
            {
              protocol: "preview",
              request: req.data,
            }
          ]
        },
    })
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
  try {
    const req = await $.post(
        "https://{{.ServerDomain}}/wallet/startIdentityRequest",
        JSON.stringify({}),
        function (data, status) {
          return data
        },
        'json').fail(function(err) {
            console.log(err);
            alert("failed to get request: "+ JSON.stringify(err));
        });
    console.log(req)
    console.log(req.data)

    window.location.href = req.url
  } catch (error) {
    console.log(error)
    alert(error)
  }
}


// URLからクエリパラメータを取得する関数
function getQueryParam(param) {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get(param);
}

function onload() {
    const sessionId = getQueryParam('session_id');

    // 'execute' パラメータが存在する場合、対応するコードを実行
    if (sessionId) {
        try {
          const req = $.post(
              "https://{{.ServerDomain}}/wallet/finishIdentityRequest",
              JSON.stringify({
                session_id: sessionId,
              }),
              function (data, status) {
                return data
              },
              'json').fail(function(err) {
                  console.log(err);
                  alert("failed to get request: "+ JSON.stringify(err));
              }).then(res => {
                alert(JSON.stringify(res));
                console.log(res)
              });
        } catch (error) {
          console.log(error)
          alert(error)
        }
    }
}

window.onload = onload
