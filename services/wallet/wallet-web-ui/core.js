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

// Utility functions
function showAlert(message, type = 'info') {
    const alertDiv = document.getElementById('alert');
    if (alertDiv) {
        alertDiv.textContent = message;
        alertDiv.className = `alert alert-${type}`;
        alertDiv.style.display = 'block';
        
        // Auto-hide after 5 seconds
        setTimeout(() => {
            alertDiv.style.display = 'none';
        }, 5000);
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

// API helper function
async function apiCall(endpoint, method = 'GET', data = null) {
    try {
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
            },
        };

        if (data && method !== 'GET') {
            options.body = JSON.stringify(data);
        }

        const response = await fetch(endpoint, options);
        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.message || 'API call failed');
        }

        return result;
    } catch (error) {
        console.error(`API call to ${endpoint} failed:`, error);
        throw error;
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
