// Main JavaScript for Google Tools Suite

// Utility Functions
function showLoading(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.style.display = 'block';
    }
}

function hideLoading(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.style.display = 'none';
    }
}

function showAlert(message, type = 'info', containerId = 'alerts') {
    const container = document.getElementById(containerId);
    if (!container) return;
    
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type}`;
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" onclick="this.parentElement.remove()">×</button>
    `;
    
    container.appendChild(alertDiv);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (alertDiv.parentElement) {
            alertDiv.remove();
        }
    }, 5000);
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('vi-VN') + ' ' + date.toLocaleTimeString('vi-VN');
}

// AJAX Helper Functions
function makeRequest(url, method = 'GET', data = null, headers = {}) {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open(method, url);
        
        // Set default headers
        if (method === 'POST' && data && typeof data === 'object') {
            xhr.setRequestHeader('Content-Type', 'application/json');
        }
        
        // Set custom headers
        Object.keys(headers).forEach(key => {
            xhr.setRequestHeader(key, headers[key]);
        });
        
        xhr.onload = function() {
            if (xhr.status >= 200 && xhr.status < 300) {
                try {
                    const response = JSON.parse(xhr.responseText);
                    resolve(response);
                } catch (e) {
                    resolve(xhr.responseText);
                }
            } else {
                reject(new Error(`HTTP ${xhr.status}: ${xhr.statusText}`));
            }
        };
        
        xhr.onerror = function() {
            reject(new Error('Network error'));
        };
        
        if (data && typeof data === 'object') {
            xhr.send(JSON.stringify(data));
        } else {
            xhr.send(data);
        }
    });
}

// Form Validation
function validateForm(formId, rules) {
    const form = document.getElementById(formId);
    if (!form) return false;
    
    let isValid = true;
    const errors = [];
    
    Object.keys(rules).forEach(fieldName => {
        const field = form.querySelector(`[name="${fieldName}"]`);
        const rule = rules[fieldName];
        
        if (!field) return;
        
        // Clear previous errors
        const errorElement = field.parentElement.querySelector('.error-message');
        if (errorElement) {
            errorElement.remove();
        }
        field.classList.remove('error');
        
        // Required validation
        if (rule.required && !field.value.trim()) {
            isValid = false;
            errors.push(`${rule.label || fieldName} là bắt buộc`);
            showFieldError(field, `${rule.label || fieldName} là bắt buộc`);
        }
        
        // Min length validation
        if (rule.minLength && field.value.length < rule.minLength) {
            isValid = false;
            errors.push(`${rule.label || fieldName} phải có ít nhất ${rule.minLength} ký tự`);
            showFieldError(field, `Phải có ít nhất ${rule.minLength} ký tự`);
        }
        
        // Email validation
        if (rule.email && field.value && !isValidEmail(field.value)) {
            isValid = false;
            errors.push(`${rule.label || fieldName} không đúng định dạng email`);
            showFieldError(field, 'Email không đúng định dạng');
        }
        
        // Custom validation
        if (rule.custom && typeof rule.custom === 'function') {
            const customResult = rule.custom(field.value);
            if (customResult !== true) {
                isValid = false;
                errors.push(customResult);
                showFieldError(field, customResult);
            }
        }
    });
    
    return { isValid, errors };
}

function showFieldError(field, message) {
    field.classList.add('error');
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-message';
    errorDiv.style.color = '#dc3545';
    errorDiv.style.fontSize = '0.875rem';
    errorDiv.style.marginTop = '5px';
    errorDiv.textContent = message;
    field.parentElement.appendChild(errorDiv);
}

function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// File Upload Helper
function handleFileUpload(inputElement, options = {}) {
    const {
        maxSize = 10 * 1024 * 1024, // 10MB default
        allowedTypes = [],
        onProgress = null,
        onSuccess = null,
        onError = null
    } = options;
    
    const file = inputElement.files[0];
    if (!file) return;
    
    // Validate file size
    if (file.size > maxSize) {
        const error = `File quá lớn. Kích thước tối đa: ${formatFileSize(maxSize)}`;
        if (onError) onError(error);
        return;
    }
    
    // Validate file type
    if (allowedTypes.length > 0 && !allowedTypes.includes(file.type)) {
        const error = `Loại file không được hỗ trợ. Chỉ chấp nhận: ${allowedTypes.join(', ')}`;
        if (onError) onError(error);
        return;
    }
    
    // Create FormData
    const formData = new FormData();
    formData.append('file', file);
    
    // Upload with progress
    const xhr = new XMLHttpRequest();
    
    if (onProgress) {
        xhr.upload.addEventListener('progress', (e) => {
            if (e.lengthComputable) {
                const percentComplete = (e.loaded / e.total) * 100;
                onProgress(percentComplete);
            }
        });
    }
    
    xhr.onload = function() {
        if (xhr.status >= 200 && xhr.status < 300) {
            try {
                const response = JSON.parse(xhr.responseText);
                if (onSuccess) onSuccess(response);
            } catch (e) {
                if (onError) onError('Lỗi xử lý phản hồi từ server');
            }
        } else {
            if (onError) onError(`Lỗi upload: ${xhr.statusText}`);
        }
    };
    
    xhr.onerror = function() {
        if (onError) onError('Lỗi kết nối mạng');
    };
    
    return xhr;
}

// Progress Bar
function updateProgressBar(progressBarId, percentage) {
    const progressBar = document.getElementById(progressBarId);
    if (progressBar) {
        progressBar.style.width = percentage + '%';
        progressBar.textContent = Math.round(percentage) + '%';
    }
}

// Local Storage Helper
function saveToLocalStorage(key, data) {
    try {
        localStorage.setItem(key, JSON.stringify(data));
        return true;
    } catch (e) {
        console.error('Error saving to localStorage:', e);
        return false;
    }
}

function loadFromLocalStorage(key, defaultValue = null) {
    try {
        const data = localStorage.getItem(key);
        return data ? JSON.parse(data) : defaultValue;
    } catch (e) {
        console.error('Error loading from localStorage:', e);
        return defaultValue;
    }
}

// Navigation Helper
function setActiveNavLink() {
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-link');
    
    navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });
}

function restoreSubmitButton(form) {
    const submitBtn = form && form.querySelector('button[type="submit"]');
    if (submitBtn) {
        submitBtn.disabled = false;
        const original = submitBtn.dataset.originalText;
        submitBtn.innerHTML = original ? original : 'Gửi';
        // Clean up after restore
        delete submitBtn.dataset.originalText;
    }
}
// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    // Set active navigation link
    setActiveNavLink();
    
    // Add loading states to forms
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function() {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                // Lưu lại nội dung nút để khôi phục sau khi xử lý xong
                submitBtn.dataset.originalText = submitBtn.innerHTML;
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<span class="spinner"></span> Đang xử lý...';
            }
        });
    });
    
    // Add close functionality to alerts
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('btn-close')) {
            e.target.parentElement.remove();
        }
    });
});

// Export functions for use in other scripts
window.GoogleToolsSuite = {
    showLoading,
    hideLoading,
    showAlert,
    formatFileSize,
    formatDate,
    makeRequest,
    validateForm,
    handleFileUpload,
    updateProgressBar,
    saveToLocalStorage,
    loadFromLocalStorage,
    setActiveNavLink,
    restoreSubmitButton
};