// Show loading overlay with custom message
function showLoading(message) {
  const overlay = document.getElementById('loadingOverlay');
  const loadingMessage = document.getElementById('loadingMessage');
  
  if (message) {
    loadingMessage.textContent = message;
  } else {
    loadingMessage.textContent = 'Processing your request...';
  }
  
  overlay.style.visibility = 'visible';
  overlay.style.opacity = '1';
}

// Hide loading overlay
function hideLoading() {
  const overlay = document.getElementById('loadingOverlay');
  overlay.style.opacity = '0';
  setTimeout(() => {
    overlay.style.visibility = 'hidden';
  }, 300);
}

// Display verification result
function displayResult(data, success = true) {
  const resultSection = document.getElementById('resultSection');
  const verificationStatus = document.getElementById('verificationStatus');
  const verificationResult = document.getElementById('verificationResult');
  
  resultSection.style.display = 'block';
  
  if (success) {
    verificationStatus.className = 'alert alert-success mb-3';
    verificationStatus.innerHTML = '<i class="fas fa-check-circle me-2"></i>Verification successful';
  } else {
    verificationStatus.className = 'alert alert-danger mb-3';
    verificationStatus.innerHTML = '<i class="fas fa-exclamation-circle me-2"></i>Verification failed';
  }
  
  if (typeof data === 'object') {
    verificationResult.textContent = JSON.stringify(data, null, 2);
  } else {
    verificationResult.textContent = data;
  }
  
  // Scroll to result section
  resultSection.scrollIntoView({ behavior: 'smooth' });
}

// Handle errors
function handleError(error) {
  console.error(error);
  let errorMessage = '';
  
  if (error.responseJSON && error.responseJSON.Error) {
    errorMessage = error.responseJSON.Error;
  } else if (error.responseText) {
    try {
      const errorObj = JSON.parse(error.responseText);
      errorMessage = errorObj.Error || error.responseText;
    } catch {
      errorMessage = error.responseText;
    }
  } else if (error.message) {
    errorMessage = error.message;
  } else {
    errorMessage = JSON.stringify(error);
  }
  
  hideLoading();
  displayResult({ error: errorMessage }, false);
}

async function getIdentityWithOpenid4VP() {
  showLoading('Requesting identity via OpenID4VP protocol...');
  
  try {
    const req = await $.post(
        "https://{{.ServerDomain}}/getIdentityRequest",
        JSON.stringify({
          protocol: "openid4vp",
        }),
        function (data, status) {
          return data;
        },
        'json'
    ).fail(function(err) {
        console.error(err);
        handleError(err);
    });
    
    console.log(req);
    console.log(req.data);
    
    showLoading('Waiting for credential from your wallet...');
    
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
    });
    
    console.log(response);
    
    showLoading('Verifying credentials...');
    
    const verifyResult = await $.post(
        "https://{{.ServerDomain}}/verifyIdentityResponse",
        JSON.stringify({
          session_id: req.session_id,
          protocol: response.protocol,
          data: response.data,
          origin: location.origin,
        }),
        function (data, status) {
          hideLoading();
          displayResult(data);
        },
        'json'
    ).fail(function(err) {
        console.error(err);
        handleError(err);
    });
    
    console.log(verifyResult);

  } catch (error) {
    console.error(error);
    handleError(error);
  }
}

async function getIdentity() {
  showLoading('Requesting identity via Preview protocol...');
  
  try {
    const req = await $.post(
        "https://{{.ServerDomain}}/getIdentityRequest",
        JSON.stringify({
          protocol: "preview",
        }),
        function (data, status) {
          return data;
        },
        'json'
    ).fail(function(err) {
        console.error(err);
        handleError(err);
    });
    
    console.log(req);
    console.log(req.data);
    
    showLoading('Waiting for credential from your wallet...');
    
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
    });
    
    console.log(response);
    
    showLoading('Verifying credentials...');
    
    const verifyResult = await $.post(
        "https://{{.ServerDomain}}/verifyIdentityResponse",
        JSON.stringify({
          session_id: req.session_id,
          protocol: response.protocol,
          data: response.data,
          origin: location.origin,
        }),
        function (data, status) {
          hideLoading();
          displayResult(data);
        },
        'json'
    ).fail(function(err) {
        console.error(err);
        handleError(err);
    });
    
    console.log(verifyResult);

  } catch (error) {
    console.error(error);
    handleError(error);
  }
}

async function getIdentifyFromEUDIW() {
  showLoading('Connecting to EU Digital Identity Wallet...');
  
  try {
    const req = await $.post(
        "https://{{.ServerDomain}}/wallet/startIdentityRequest",
        JSON.stringify({}),
        function (data, status) {
          return data;
        },
        'json'
    ).fail(function(err) {
        console.error(err);
        handleError(err);
    });
    
    console.log(req);
    console.log(req.data);
    
    // Redirect to the authentication URL
    window.location.href = req.url;
  } catch (error) {
    console.error(error);
    handleError(error);
  }
}

// Get query parameter from URL
function getQueryParam(param) {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get(param);
}

function onload() {
    const sessionId = getQueryParam('session_id');

    // If session_id exists in URL, process the response
    if (sessionId) {
        showLoading('Completing verification process...');
        
        try {
          const req = $.post(
              "https://{{.ServerDomain}}/wallet/finishIdentityRequest",
              JSON.stringify({
                session_id: sessionId,
              }),
              function (data, status) {
                return data;
              },
              'json'
          ).fail(function(err) {
              console.error(err);
              handleError(err);
          }).then(res => {
            hideLoading();
            displayResult(res);
            console.log(res);
            
            // Remove the session_id from the URL without reloading the page
            const newUrl = window.location.pathname;
            window.history.pushState({ path: newUrl }, '', newUrl);
          });
        } catch (error) {
          console.error(error);
          handleError(error);
        }
    }
}

window.onload = onload;