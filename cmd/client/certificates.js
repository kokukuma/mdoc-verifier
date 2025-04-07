// JavaScript for Certificate Management

// Base URL setting
// Using Go template variable
const API_BASE_URL = '{{.ServerAPIURL}}'; // Value provided by server

// Certificate API endpoint
const CERT_API_URL = `${API_BASE_URL}/api/certificates`;
const CLIENT_CERT_API_URL = `${API_BASE_URL}/api/client-cert-chain`;

// Loading overlay show/hide
function showLoading(message = 'Processing...') {
  document.getElementById('loadingMessage').textContent = message;
  document.getElementById('loadingOverlay').style.visibility = 'visible';
  document.getElementById('loadingOverlay').style.opacity = '1';
}

function hideLoading() {
  document.getElementById('loadingOverlay').style.opacity = '0';
  setTimeout(() => {
    document.getElementById('loadingOverlay').style.visibility = 'hidden';
  }, 300);
}

// Display toast notification
function showToast(message, type = 'success') {
  // Remove existing toasts
  const existingToasts = document.querySelectorAll('.toast-container');
  existingToasts.forEach(toast => {
    toast.remove();
  });

  // 新しいトーストを作成
  const toastContainer = document.createElement('div');
  toastContainer.className = 'toast-container position-fixed bottom-0 end-0 p-3';
  toastContainer.style.zIndex = '5';

  const toast = document.createElement('div');
  toast.className = `toast align-items-center text-white bg-${type} border-0`;
  toast.setAttribute('role', 'alert');
  toast.setAttribute('aria-live', 'assertive');
  toast.setAttribute('aria-atomic', 'true');

  const toastBody = document.createElement('div');
  toastBody.className = 'd-flex';

  const toastMessage = document.createElement('div');
  toastMessage.className = 'toast-body';
  toastMessage.textContent = message;

  const closeButton = document.createElement('button');
  closeButton.type = 'button';
  closeButton.className = 'btn-close btn-close-white me-2 m-auto';
  closeButton.setAttribute('data-bs-dismiss', 'toast');
  closeButton.setAttribute('aria-label', 'Close');

  toastBody.appendChild(toastMessage);
  toastBody.appendChild(closeButton);
  toast.appendChild(toastBody);
  toastContainer.appendChild(toast);
  document.body.appendChild(toastContainer);

  const bsToast = new bootstrap.Toast(toast, {
    animation: true,
    autohide: true,
    delay: 3000
  });
  bsToast.show();
}

// Fetch certificate list
async function fetchCertificates() {
  try {
    showLoading('Loading certificate list...');
    const response = await fetch(CERT_API_URL);
    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }
    const certs = await response.json();
    return certs;
  } catch (error) {
    console.error('Error fetching certificates:', error);
    showToast('Failed to fetch certificate list', 'danger');
    return [];
  } finally {
    hideLoading();
  }
}

// Fetch certificate details
async function fetchCertificateDetails(filename) {
  try {
    showLoading('Loading certificate details...');
    const response = await fetch(`${CERT_API_URL}/${filename}`);
    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }
    const cert = await response.json();
    return cert;
  } catch (error) {
    console.error('Error fetching certificate details:', error);
    showToast('Failed to fetch certificate details', 'danger');
    return null;
  } finally {
    hideLoading();
  }
}

// Add certificate (upload)
async function uploadCertificate(formData) {
  try {
    showLoading('Uploading certificate...');
    const response = await fetch(CERT_API_URL, {
      method: 'POST',
      body: formData
    });
    
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || `API error: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error uploading certificate:', error);
    showToast(`Failed to upload certificate: ${error.message}`, 'danger');
    return null;
  } finally {
    hideLoading();
  }
}

// Add certificate (JSON)
async function addCertificateJson(filename, pemData) {
  try {
    showLoading('Adding certificate...');
    const response = await fetch(`${CERT_API_URL}/json`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        filename: filename,
        pem_data: pemData
      })
    });
    
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || `API error: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error adding certificate:', error);
    showToast(`Failed to add certificate: ${error.message}`, 'danger');
    return null;
  } finally {
    hideLoading();
  }
}

// Delete certificate
async function deleteCertificate(filename) {
  try {
    showLoading('Deleting certificate...');
    const response = await fetch(`${CERT_API_URL}/${filename}`, {
      method: 'DELETE'
    });
    
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || `API error: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error deleting certificate:', error);
    showToast(`Failed to delete certificate: ${error.message}`, 'danger');
    return null;
  } finally {
    hideLoading();
  }
}

// Reload certificates
async function reloadCertificates() {
  try {
    showLoading('Reloading certificates...');
    const response = await fetch(`${CERT_API_URL}/reload`, {
      method: 'POST'
    });
    
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || `API error: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error reloading certificates:', error);
    showToast(`Failed to reload certificates: ${error.message}`, 'danger');
    return null;
  } finally {
    hideLoading();
  }
}

// Update certificate list display
function updateCertificateList(certificates) {
  const listContainer = document.getElementById('certificatesList');
  
  if (!certificates || certificates.length === 0) {
    listContainer.innerHTML = `
      <div class="text-center py-4 text-muted">
        <i class="fas fa-info-circle fa-2x mb-3"></i>
        <p>No certificates found</p>
      </div>
    `;
    return;
  }
  
  // 現在日付
  const now = new Date();
  
  let html = '';
  certificates.forEach(cert => {
    // 有効期限の確認
    const expiryDate = new Date(cert.valid_to);
    const daysDiff = Math.floor((expiryDate - now) / (1000 * 60 * 60 * 24));
    
    let statusClass = '';
    let statusBadge = '';
    
    if (expiryDate < now) {
      statusClass = 'expired';
      statusBadge = '<span class="badge bg-danger ms-2">Expired</span>';
    } else if (daysDiff < 30) {
      statusClass = 'warning';
      statusBadge = '<span class="badge bg-warning text-dark ms-2">Expiring soon</span>';
    }
    
    html += `
      <div class="cert-item ${statusClass}" data-filename="${cert.filename}">
        <div class="d-flex align-items-start">
          <div>
            <h6 class="mb-1">
              <i class="fas fa-certificate me-2"></i>
              ${cert.filename}
              ${statusBadge}
            </h6>
            <small class="text-muted d-block">Issuer: ${cert.issuer}</small>
            <small class="text-muted d-block">Valid until: ${cert.valid_to}</small>
          </div>
        </div>
      </div>
    `;
  });
  
  listContainer.innerHTML = html;
  
  // 証明書アイテムのクリックイベント
  document.querySelectorAll('.cert-item').forEach(item => {
    item.addEventListener('click', function() {
      const filename = this.getAttribute('data-filename');
      showCertificateDetails(filename);
      
      // 選択状態の更新
      document.querySelectorAll('.cert-item').forEach(i => {
        i.classList.remove('active', 'bg-light');
      });
      this.classList.add('active', 'bg-light');
    });
  });
}

// Display certificate details
async function showCertificateDetails(filename) {
  const detailsContainer = document.getElementById('certDetailsContainer');
  
  detailsContainer.innerHTML = `
    <div class="text-center py-4">
      <div class="spinner-border text-primary" role="status"></div>
      <p class="mt-3">Loading certificate details...</p>
    </div>
  `;
  
  const certDetails = await fetchCertificateDetails(filename);
  if (!certDetails) {
    detailsContainer.innerHTML = `
      <div class="alert alert-danger">
        <i class="fas fa-exclamation-circle me-2"></i>
        Failed to fetch certificate details
      </div>
    `;
    return;
  }
  
  const info = certDetails.info;
  const pemData = certDetails.pem_data;
  
  // Validity status
  const now = new Date();
  const expiryDate = new Date(info.valid_to);
  const daysDiff = Math.floor((expiryDate - now) / (1000 * 60 * 60 * 24));
  
  let validityBadge = `<span class="badge bg-success">Valid</span>`;
  
  if (expiryDate < now) {
    validityBadge = `<span class="badge bg-danger">Expired</span>`;
  } else if (daysDiff < 30) {
    validityBadge = `<span class="badge bg-warning text-dark">Expiring soon (${daysDiff} days left)</span>`;
  }
  
  detailsContainer.innerHTML = `
    <div class="cert-details-container">
      <div class="d-flex justify-content-between align-items-start mb-4">
        <h5 class="mb-2">
          <i class="fas fa-certificate me-2"></i>
          ${info.filename}
        </h5>
        <div>
          ${validityBadge}
        </div>
      </div>
      
      <div class="cert-meta mb-4">
        <div class="cert-meta-item">
          <strong>Subject:</strong>
          <div class="text-muted">${info.subject}</div>
        </div>
        <div class="cert-meta-item">
          <strong>Issuer:</strong>
          <div class="text-muted">${info.issuer}</div>
        </div>
        <div class="cert-meta-item">
          <strong>Valid From:</strong>
          <div class="text-muted">${info.valid_from}</div>
        </div>
        <div class="cert-meta-item">
          <strong>Valid To:</strong>
          <div class="text-muted">${info.valid_to}</div>
        </div>
        <div class="cert-meta-item">
          <strong>Fingerprint:</strong>
          <div class="text-muted">${info.fingerprint}</div>
        </div>
      </div>
      
      <h6 class="mb-2">Certificate Content (PEM format):</h6>
      <div class="pem-content">${pemData}</div>
      
      <div class="mt-4 d-flex justify-content-between">
        <button class="btn btn-sm btn-outline-primary download-cert-btn" 
                data-filename="${info.filename}" 
                data-pemdata="${encodeURIComponent(pemData)}">
          <i class="fas fa-download me-2"></i>Download
        </button>
        <button class="btn btn-sm btn-outline-danger delete-cert-btn" 
                data-filename="${info.filename}">
          <i class="fas fa-trash-alt me-2"></i>Delete
        </button>
      </div>
    </div>
  `;
  
  // 削除ボタンのクリックイベント
  document.querySelector('#certDetailsContainer .delete-cert-btn').addEventListener('click', function() {
    const filename = this.getAttribute('data-filename');
    showDeleteConfirmation(filename);
  });
  
  // ダウンロードボタンのクリックイベント
  document.querySelector('#certDetailsContainer .download-cert-btn').addEventListener('click', function() {
    const filename = this.getAttribute('data-filename');
    const pemData = decodeURIComponent(this.getAttribute('data-pemdata'));
    downloadCertificate(filename, pemData);
  });
}

// 削除確認ダイアログの表示
function showDeleteConfirmation(filename) {
  const modal = new bootstrap.Modal(document.getElementById('deleteCertModal'));
  document.getElementById('deleteCertName').textContent = filename;
  
  // 削除確認ボタンのイベントリスナーを一度削除して再設定
  const confirmBtn = document.getElementById('confirmDeleteButton');
  const newBtn = confirmBtn.cloneNode(true);
  confirmBtn.parentNode.replaceChild(newBtn, confirmBtn);
  
  newBtn.addEventListener('click', async function() {
    modal.hide();
    const result = await deleteCertificate(filename);
    if (result) {
      showToast('Certificate deleted successfully', 'success');
      init(); // Reload list
      
      // 詳細表示をクリア
      document.getElementById('certDetailsContainer').innerHTML = `
        <div class="text-center py-5 text-muted">
          <i class="fas fa-certificate fa-3x mb-3"></i>
          <p>左側の一覧から証明書を選択すると、詳細が表示されます</p>
        </div>
      `;
    }
  });
  
  modal.show();
}

// Certificate search function
function setupSearch() {
  const searchInput = document.getElementById('certSearchInput');
  searchInput.addEventListener('input', function() {
    const searchTerm = this.value.toLowerCase();
    const certItems = document.querySelectorAll('.cert-item');
    
    certItems.forEach(item => {
      const filename = item.getAttribute('data-filename').toLowerCase();
      const issuer = item.querySelector('small:nth-of-type(1)').textContent.toLowerCase();
      
      if (filename.includes(searchTerm) || issuer.includes(searchTerm)) {
        item.style.display = '';
      } else {
        item.style.display = 'none';
      }
    });
    
    // Message for no search results
    const visibleItems = document.querySelectorAll('.cert-item[style=""]').length;
    if (visibleItems === 0 && searchTerm !== '') {
      const noResults = document.createElement('div');
      noResults.className = 'text-center py-3 text-muted no-results';
      noResults.innerHTML = `
        <i class="fas fa-search me-2"></i>
        No certificates found matching "${searchTerm}"
      `;
      
      // Remove existing no-results elements
      const existing = document.querySelector('.no-results');
      if (existing) {
        existing.remove();
      }
      
      document.getElementById('certificatesList').appendChild(noResults);
    } else {
      // Remove no-results element if it exists
      const existing = document.querySelector('.no-results');
      if (existing) {
        existing.remove();
      }
    }
  });
}

// Initialize add certificate modal
function setupAddCertModal() {
  const addCertButton = document.getElementById('addCertButton');
  const uploadForm = document.getElementById('uploadCertForm');
  const pasteForm = document.getElementById('pasteCertForm');
  const uploadTab = document.getElementById('upload-tab');
  const pasteTab = document.getElementById('paste-tab');
  
  // アクティブなタブを追跡する変数
  let activeTab = 'upload';
  
  // タブ切り替えイベント
  uploadTab.addEventListener('shown.bs.tab', () => {
    activeTab = 'upload';
  });
  
  pasteTab.addEventListener('shown.bs.tab', () => {
    activeTab = 'paste';
  });
  
  // Add button click event
  addCertButton.addEventListener('click', async function() {
    // Form validation
    let isValid = false;
    
    if (activeTab === 'upload') {
      isValid = uploadForm.checkValidity();
      if (!isValid) {
        uploadForm.reportValidity();
        return;
      }
      
      const certFile = document.getElementById('certFile').files[0];
      
      if (!certFile) {
        showToast('Please select a certificate file', 'warning');
        return;
      }
      
      // Create FormData
      const formData = new FormData();
      formData.append('certificate', certFile);
      
      // Upload certificate
      const result = await uploadCertificate(formData);
      if (result) {
        showToast('証明書を追加しました', 'success');
        // モーダルを閉じて一覧を再読み込み
        bootstrap.Modal.getInstance(document.getElementById('addCertModal')).hide();
        uploadForm.reset();
        init();
      }
      
    } else { // paste tab
      isValid = pasteForm.checkValidity();
      if (!isValid) {
        pasteForm.reportValidity();
        return;
      }
      
      filename = document.getElementById('pasteFilename').value;
      const pemData = document.getElementById('certContent').value;
      
      if (!pemData.includes('-----BEGIN CERTIFICATE-----') || !pemData.includes('-----END CERTIFICATE-----')) {
        showToast('Please enter a valid PEM-formatted certificate', 'warning');
        return;
      }
      
      // Add certificate
      const result = await addCertificateJson(filename, pemData);
      if (result) {
        showToast('Certificate added successfully', 'success');
        // Close modal and reload list
        bootstrap.Modal.getInstance(document.getElementById('addCertModal')).hide();
        pasteForm.reset();
        init();
      }
    }
  });
  
  // Reset forms when modal is closed
  document.getElementById('addCertModal').addEventListener('hidden.bs.modal', function() {
    uploadForm.reset();
    pasteForm.reset();
  });
}

// Initialize certificate reload button
function setupReloadButton() {
  document.getElementById('reloadCertsBtn').addEventListener('click', async function() {
    const result = await reloadCertificates();
    if (result) {
      showToast('Certificates reloaded successfully', 'success');
      init(); // Reload list
    }
  });
}

// Initialization
async function init() {
  const certificates = await fetchCertificates();
  updateCertificateList(certificates);
  setupSearch();
}

// Download certificate
function downloadCertificate(filename, pemData) {
  // Create Blob object
  const blob = new Blob([pemData], { type: 'application/x-x509-ca-cert' });
  // Create URL object
  const url = URL.createObjectURL(blob);
  
  // Create download link element
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  
  // Execute download
  a.click();
  
  // Clean up element and URL
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  
  showToast(`Certificate "${filename}" downloaded successfully`, 'success');
}

// Fetch client certificate chain
async function fetchClientCertChain() {
  try {
    showLoading('Loading client certificate chain...');
    const response = await fetch(CLIENT_CERT_API_URL);
    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    console.error('Error fetching client certificate chain:', error);
    showToast('Failed to fetch client certificate chain', 'danger');
    return null;
  } finally {
    hideLoading();
  }
}

// Update client certificate tab
async function updateClientCertTab() {
  const clientCertChainContainer = document.getElementById('clientCertChain');
  const clientCertData = await fetchClientCertChain();
  
  if (!clientCertData || !clientCertData.certificates || clientCertData.certificates.length === 0) {
    clientCertChainContainer.innerHTML = `
      <div class="alert alert-warning">
        <i class="fas fa-exclamation-triangle me-2"></i>
        No client certificate chain available or could not be loaded.
      </div>
    `;
    return;
  }
  
  // Join all certificates for display
  const chainContent = clientCertData.certificates.join('\n\n');
  clientCertChainContainer.innerHTML = `<pre>${chainContent}</pre>`;
  
  // Setup download button
  document.getElementById('downloadClientCertBtn').addEventListener('click', function() {
    downloadCertificate('client_certificate_chain.pem', chainContent);
  });
}

// Setup certificate tabs
function setupCertTabs() {
  // Event listener for tab change
  document.getElementById('client-tab').addEventListener('shown.bs.tab', function(e) {
    updateClientCertTab();
  });
}

// Page load complete event handler
document.addEventListener('DOMContentLoaded', function() {
  init();
  setupAddCertModal();
  setupReloadButton();
  setupCertTabs();
});
