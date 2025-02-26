// Helper function to get selected attributes
function getSelectedAttributes() {
  const selectedAttributes = [];
  
  // Get all checked checkboxes
  document.querySelectorAll('input[type="checkbox"][id^="attr_"]:checked').forEach(function(checkbox) {
    selectedAttributes.push(checkbox.value);
  });
  
  return selectedAttributes;
}

// Function to select or deselect all attributes
function selectAllAttributes(select) {
  document.querySelectorAll('input[type="checkbox"][id^="attr_"]').forEach(function(checkbox) {
    checkbox.checked = select;
  });
}

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


// Create a table for displaying verification results with namespace, identifier, and value columns
function createResultTable(data) {
  console.log("Creating table from data:", data);
  
  // Create container div
  var table = document.createElement('table');
  table.className = 'table table-striped table-hover';
  
  // Create header
  var thead = document.createElement('thead');
  thead.className = 'table-light';
  var headerRow = document.createElement('tr');
  
  var thNamespace = document.createElement('th');
  thNamespace.style.width = '30%';
  thNamespace.textContent = 'Namespace';
  
  var thIdentifier = document.createElement('th');
  thIdentifier.style.width = '30%';
  thIdentifier.textContent = 'Identifier';
  
  var thValue = document.createElement('th');
  thValue.style.width = '40%';
  thValue.textContent = 'Value';
  
  headerRow.appendChild(thNamespace);
  headerRow.appendChild(thIdentifier);
  headerRow.appendChild(thValue);
  thead.appendChild(headerRow);
  table.appendChild(thead);
  
  // Create body
  var tbody = document.createElement('tbody');
  
  // Track if we've added any data
  var rowsAdded = false;
  
  // Process the data in the exact format from the server
  if (data.elements && Array.isArray(data.elements)) {
    // Loop through each element in the array
    data.elements.forEach(function(element) {
      if (element.namespace && element.identifier && element.hasOwnProperty('value')) {
        // Add row for this element with its namespace, identifier, and value
        addRow(tbody, element.namespace, element.identifier, element.value);
        rowsAdded = true;
      }
    });
  }
  
  // Fallback for older data format
  if (!rowsAdded && data.namespaces) {
    // Check for elements in namespaces
    if (data.namespaces.elements) {
      try {
        // This is a different structure, try to process it
        var elementsData = data.namespaces.elements;
        
        Object.keys(elementsData).forEach(function(namespaceKey) {
          var namespaceObj = elementsData[namespaceKey];
          
          Object.keys(namespaceObj).forEach(function(elementKey) {
            var elementValue = namespaceObj[elementKey];
            addRow(tbody, namespaceKey, elementKey, elementValue);
            rowsAdded = true;
          });
        });
      } catch (e) {
        console.error("Error processing namespaces.elements:", e);
      }
    }
    
    // If still no data, try other namespaces
    if (!rowsAdded) {
      Object.keys(data.namespaces).forEach(function(namespace) {
        // Skip general namespace
        if (namespace === 'general') {
          return;
        }
        
        var nsData = data.namespaces[namespace];
        
        // Process each field in the namespace
        Object.keys(nsData).forEach(function(identifier) {
          var value = nsData[identifier];
          addRow(tbody, namespace, identifier, value);
          rowsAdded = true;
        });
      });
    }
  }
  
  // If we still have no rows, display a message
  if (!rowsAdded) {
    var row = document.createElement('tr');
    var cell = document.createElement('td');
    cell.colSpan = 3;
    cell.className = 'text-center text-muted';
    cell.textContent = 'No credential data available';
    row.appendChild(cell);
    tbody.appendChild(row);
  }
  
  table.appendChild(tbody);
  
  // Add document type header if available
  if (data.docType) {
    var docTypeDiv = document.createElement('div');
    docTypeDiv.className = 'alert alert-primary mb-3';
    docTypeDiv.innerHTML = '<strong>Document Type:</strong> ' + data.docType;
    
    var container = document.createElement('div');
    container.appendChild(docTypeDiv);
    container.appendChild(table);
    return container;
  }
  
  return table;
}

// Helper function to add a row to the table
function addRow(tbody, namespace, identifier, value) {
  var row = document.createElement('tr');
  
  // Namespace cell
  var nsCell = document.createElement('td');
  nsCell.innerHTML = '<span class="text-primary">' + namespace + '</span>';
  
  // Identifier cell
  var idCell = document.createElement('td');
  idCell.innerHTML = '<strong>' + identifier + '</strong>';
  
  // Value cell
  var valueCell = document.createElement('td');
  
  // Format the value based on its type
  if (value === null || value === undefined) {
    valueCell.innerHTML = '<em class="text-muted">null</em>';
  } else if (typeof value === 'boolean') {
    valueCell.innerHTML = value ? 
      '<span class="badge bg-success">Yes</span>' : 
      '<span class="badge bg-danger">No</span>';
  } else if (typeof value === 'object' && !Array.isArray(value)) {
    // For objects, create a JSON string
    valueCell.innerHTML = '<pre class="mb-0" style="max-height: 100px; overflow-y: auto;">' + 
                        JSON.stringify(value, null, 2) + '</pre>';
  } else if (Array.isArray(value)) {
    if (value.length === 0) {
      valueCell.innerHTML = '<em class="text-muted">Empty array</em>';
    } else {
      // For simple arrays, display as comma-separated list
      if (value.every(item => typeof item !== 'object' || item === null)) {
        valueCell.textContent = value.join(', ');
      } else {
        // For complex arrays, create a JSON string
        valueCell.innerHTML = '<pre class="mb-0" style="max-height: 100px; overflow-y: auto;">' + 
                            JSON.stringify(value, null, 2) + '</pre>';
      }
    }
  } else if (typeof value === 'string') {
    // Check if it's a URL
    if (value.match(/^https?:\/\//i)) {
      valueCell.innerHTML = '<a href="' + value + '" target="_blank">' + value + '</a>';
    } else {
      valueCell.textContent = value;
    }
  } else {
    // Other primitive values
    valueCell.textContent = value;
  }
  
  row.appendChild(nsCell);
  row.appendChild(idCell);
  row.appendChild(valueCell);
  tbody.appendChild(row);
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
    try {
      // Clear previous content
      while (verificationResult.firstChild) {
        verificationResult.removeChild(verificationResult.firstChild);
      }
      
      // Add toggle button
      var toggleButton = document.createElement('button');
      toggleButton.className = 'btn btn-sm btn-outline-secondary mb-3';
      toggleButton.textContent = 'Toggle JSON View';
      toggleButton.onclick = function() {
        document.getElementById('tableView').style.display = 
          document.getElementById('tableView').style.display === 'none' ? 'block' : 'none';
        document.getElementById('jsonView').style.display = 
          document.getElementById('jsonView').style.display === 'none' ? 'block' : 'none';
      };
      verificationResult.appendChild(toggleButton);
      
      // Create table view
      var tableView = document.createElement('div');
      tableView.id = 'tableView';
      tableView.appendChild(createResultTable(data));
      verificationResult.appendChild(tableView);
      
      // Create JSON view (hidden by default)
      var jsonView = document.createElement('div');
      jsonView.id = 'jsonView';
      jsonView.style.display = 'none';
      
      var pre = document.createElement('pre');
      pre.textContent = JSON.stringify(data, null, 2);
      jsonView.appendChild(pre);
      
      verificationResult.appendChild(jsonView);
    } catch (error) {
      console.error('Error creating table:', error);
      // Fallback to JSON
      verificationResult.innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
    }
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
  // Get selected attributes
  const selectedAttributes = getSelectedAttributes();
  
  if (selectedAttributes.length === 0) {
    alert("Please select at least one attribute to request.");
    return;
  }
  
  showLoading('Requesting identity via OpenID4VP protocol...');
  
  try {
    const req = await $.post(
        "https://{{.ServerDomain}}/getIdentityRequest",
        JSON.stringify({
          protocol: "openid4vp",
          attributes: selectedAttributes
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
  // Get selected attributes
  const selectedAttributes = getSelectedAttributes();
  
  if (selectedAttributes.length === 0) {
    alert("Please select at least one attribute to request.");
    return;
  }
  
  showLoading('Requesting identity via Preview protocol...');
  
  try {
    const req = await $.post(
        "https://{{.ServerDomain}}/getIdentityRequest",
        JSON.stringify({
          protocol: "preview",
          attributes: selectedAttributes
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
  // Get selected attributes
  const selectedAttributes = getSelectedAttributes();
  
  if (selectedAttributes.length === 0) {
    alert("Please select at least one attribute to request.");
    return;
  }
  
  showLoading('Connecting to EU Digital Identity Wallet...');
  
  try {
    const req = await $.post(
        "https://{{.ServerDomain}}/wallet/startIdentityRequest",
        JSON.stringify({
          attributes: selectedAttributes
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