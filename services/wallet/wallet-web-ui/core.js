// Core application functionality
class WalletApp {
    constructor() {
        this.user = null;
        this.connectionStatus = false;
        this.checkInterval = null;
    }

    async initialize() {
        await this.checkAuth();
        await this.checkConnection();
        this.startConnectionMonitoring();
        this.loadInitialData();
    }

    async checkAuth() {
        try {
            const response = await fetch('/api/user');
            if (response.ok) {
                const result = await response.json();
                this.user = result.data;
                this.updateUserInfo();
            } else {
                window.location.href = '/login';
            }
        } catch (error) {
            console.error('Auth check failed:', error);
            window.location.href = '/login';
        }
    }

    async checkConnection() {
        try {
            const response = await fetch('/api/status');
            const result = await response.json();
            this.connectionStatus = result.success;
            this.updateConnectionStatus();
        } catch (error) {
            this.connectionStatus = false;
            this.updateConnectionStatus();
        }
    }

    startConnectionMonitoring() {
        this.checkInterval = setInterval(() => {
            this.checkConnection();
        }, 10000); // Check every 10 seconds
    }

    updateUserInfo() {
        const userInfo = document.getElementById('userInfo');
        if (userInfo && this.user) {
            userInfo.textContent = `Welcome, ${this.user.username}`;
        }
    }

    updateConnectionStatus() {
        const statusElement = document.getElementById('connectionStatus');
        if (statusElement) {
            if (this.connectionStatus) {
                statusElement.textContent = 'Connected';
                statusElement.className = 'status status-connected';
            } else {
                statusElement.textContent = 'Disconnected';
                statusElement.className = 'status status-disconnected';
            }
        }
    }

    loadInitialData() {
        // Load initial data for all sections
        loadWallets();
        loadTransactions();
        loadOTCOrders();
    }

    destroy() {
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
        }
    }
}

// Global app instance
let app = null;

// Initialize dashboard
async function initializeDashboard() {
    app = new WalletApp();
    await app.initialize();
}

// Enhanced Utility functions
function showAlert(message, type = 'info', duration = 5000) {
    const alertDiv = document.getElementById('alert');
    if (alertDiv) {
        // Clear any existing timeout
        if (alertDiv.hideTimeout) {
            clearTimeout(alertDiv.hideTimeout);
        }

        alertDiv.textContent = message;
        alertDiv.className = `alert alert-${type}`;
        alertDiv.style.display = 'block';

        // Add close button for persistent alerts
        if (type === 'error' || duration === 0) {
            alertDiv.innerHTML = `
                <span>${message}</span>
                <button class="alert-close" onclick="hideAlert()">&times;</button>
            `;
        }

        // Auto-hide after specified duration (0 = no auto-hide)
        if (duration > 0) {
            alertDiv.hideTimeout = setTimeout(() => {
                hideAlert();
            }, duration);
        }
    }
}

function hideAlert() {
    const alertDiv = document.getElementById('alert');
    if (alertDiv) {
        alertDiv.style.display = 'none';
        if (alertDiv.hideTimeout) {
            clearTimeout(alertDiv.hideTimeout);
        }
    }
}

function showLoadingState(elementId, show = true, message = 'Loading...') {
    const element = document.getElementById(elementId);
    if (element) {
        if (show) {
            element.innerHTML = `
                <div class="loading-state">
                    <div class="loading-spinner"></div>
                    <p>${message}</p>
                </div>
            `;
        }
    }
}

function showErrorState(elementId, message, retryFunction = null) {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = `
            <div class="error-state">
                <div class="error-icon">⚠️</div>
                <p class="error-message">${message}</p>
                ${retryFunction ? `<button class="btn btn-secondary" onclick="${retryFunction}()">Try Again</button>` : ''}
            </div>
        `;
    }
}

function showEmptyState(elementId, title, description, actionText = null, actionFunction = null) {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">📭</div>
                <h4>${title}</h4>
                <p class="text-muted">${description}</p>
                ${actionText && actionFunction ? `<button class="btn btn-primary" onclick="${actionFunction}()">${actionText}</button>` : ''}
            </div>
        `;
    }
}

function formatDate(timestamp) {
    return new Date(timestamp).toLocaleString();
}

function formatAmount(amount) {
    return new Intl.NumberFormat().format(amount);
}

function truncateAddress(address, length = 8) {
    if (!address) return '';
    if (address.length <= length * 2) return address;
    return `${address.slice(0, length)}...${address.slice(-length)}`;
}

// Enhanced API helper function with retry logic and better error handling
async function apiCall(endpoint, method = 'GET', data = null, options = {}) {
    const {
        retries = 2,
        timeout = 10000,
        showLoading = false,
        loadingElement = null
    } = options;

    if (showLoading && loadingElement) {
        showLoadingState(loadingElement, true);
    }

    for (let attempt = 0; attempt <= retries; attempt++) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), timeout);

            const fetchOptions = {
                method,
                headers: {
                    'Content-Type': 'application/json',
                },
                signal: controller.signal,
            };

            if (data && method !== 'GET') {
                fetchOptions.body = JSON.stringify(data);
            }

            const response = await fetch(endpoint, fetchOptions);
            clearTimeout(timeoutId);

            if (!response.ok) {
                const errorText = await response.text();
                let errorMessage;

                try {
                    const errorJson = JSON.parse(errorText);
                    errorMessage = errorJson.message || errorJson.error || 'API call failed';
                } catch {
                    errorMessage = `HTTP ${response.status}: ${response.statusText}`;
                }

                throw new APIError(errorMessage, response.status, endpoint);
            }

            const result = await response.json();

            if (showLoading && loadingElement) {
                showLoadingState(loadingElement, false);
            }

            return result;

        } catch (error) {
            console.error(`API call to ${endpoint} failed (attempt ${attempt + 1}):`, error);

            // Don't retry on certain errors
            if (error instanceof APIError && error.status >= 400 && error.status < 500) {
                if (showLoading && loadingElement) {
                    showErrorState(loadingElement, error.message);
                }
                throw error;
            }

            // If this was the last attempt, throw the error
            if (attempt === retries) {
                if (showLoading && loadingElement) {
                    showErrorState(loadingElement, getErrorMessage(error), 'retryLastOperation');
                }
                throw error;
            }

            // Wait before retrying (exponential backoff)
            await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 1000));
        }
    }
}

// Custom error class for API errors
class APIError extends Error {
    constructor(message, status, endpoint) {
        super(message);
        this.name = 'APIError';
        this.status = status;
        this.endpoint = endpoint;
    }
}

// Helper function to get user-friendly error messages
function getErrorMessage(error) {
    if (error instanceof APIError) {
        return error.message;
    }

    if (error.name === 'AbortError') {
        return 'Request timed out. Please check your connection and try again.';
    }

    if (error.message.includes('Failed to fetch')) {
        return 'Unable to connect to server. Please check your internet connection.';
    }

    return error.message || 'An unexpected error occurred. Please try again.';
}

// Global retry function for error states
let lastFailedOperation = null;
function retryLastOperation() {
    if (lastFailedOperation) {
        lastFailedOperation();
    }
}

// Modal helper functions
function createModal(title, content, actions = []) {
    const modalId = 'modal-' + Date.now();
    const modal = document.createElement('div');
    modal.id = modalId;
    modal.className = 'modal-overlay';
    
    modal.innerHTML = `
        <div class="modal">
            <div class="modal-header">
                <h3>${title}</h3>
                <button class="modal-close" onclick="closeModal('${modalId}')">&times;</button>
            </div>
            <div class="modal-content">
                ${content}
            </div>
            <div class="modal-actions">
                ${actions.map(action => `<button class="btn ${action.class}" onclick="${action.onclick}">${action.text}</button>`).join('')}
                <button class="btn btn-secondary" onclick="closeModal('${modalId}')">Cancel</button>
            </div>
        </div>
    `;
    
    document.getElementById('modalsContainer').appendChild(modal);
    return modalId;
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.remove();
    }
}

// Form helper functions
function createFormField(label, type, id, placeholder = '', required = true) {
    return `
        <div class="form-field">
            <label for="${id}">${label}${required ? ' *' : ''}</label>
            <input type="${type}" id="${id}" placeholder="${placeholder}" ${required ? 'required' : ''} class="form-input">
        </div>
    `;
}

function getFormData(formId) {
    const form = document.getElementById(formId);
    if (!form) return null;
    
    const formData = new FormData(form);
    const data = {};
    
    for (let [key, value] of formData.entries()) {
        data[key] = value;
    }
    
    return data;
}

// Logout function
async function logout() {
    try {
        await fetch('/api/logout', { method: 'POST' });
        if (app) {
            app.destroy();
        }
        window.location.href = '/login';
    } catch (error) {
        console.error('Logout failed:', error);
        window.location.href = '/login';
    }
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (app) {
        app.destroy();
    }
});
