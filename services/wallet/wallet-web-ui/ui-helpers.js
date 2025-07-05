// UI Helper Functions and Transaction Management

// Transaction History Functions
async function loadTransactions() {
    const transactionsList = document.getElementById('transactionsList');
    transactionsList.innerHTML = '<p class="loading">Loading transactions...</p>';
    
    try {
        const result = await apiCall('/api/transactions?limit=20');
        
        if (result.success) {
            const transactions = result.data || [];
            
            if (transactions.length === 0) {
                transactionsList.innerHTML = `
                    <div class="empty-state">
                        <p>No transactions found</p>
                        <p class="text-muted">Your transactions will appear here once you start using the wallet</p>
                    </div>
                `;
            } else {
                transactionsList.innerHTML = `
                    <div class="transactions-list">
                        ${transactions.map(tx => createTransactionCard(tx)).join('')}
                    </div>
                `;
            }
            showAlert('Transactions loaded successfully!', 'success');
        } else {
            transactionsList.innerHTML = `<p class="error">Error loading transactions: ${result.message}</p>`;
        }
    } catch (error) {
        transactionsList.innerHTML = `<p class="error">Error loading transactions: ${error.message}</p>`;
        showAlert('Failed to load transactions: ' + error.message, 'error');
    }
}

function createTransactionCard(tx) {
    const typeClass = getTransactionTypeClass(tx.type);
    const statusClass = getTransactionStatusClass(tx.status);
    
    return `
        <div class="transaction-card ${typeClass}">
            <div class="tx-header">
                <div class="tx-type">
                    <span class="tx-icon">${getTransactionIcon(tx.type)}</span>
                    <span class="tx-type-text">${tx.type || 'Unknown'}</span>
                </div>
                <div class="tx-status ${statusClass}">${tx.status || 'Pending'}</div>
            </div>
            
            <div class="tx-details">
                <div class="tx-amount">
                    <span class="amount ${tx.type === 'transfer' && tx.from === app?.user?.address ? 'negative' : 'positive'}">
                        ${tx.type === 'transfer' && tx.from === app?.user?.address ? '-' : '+'}${formatAmount(tx.amount || 0)} BHX
                    </span>
                </div>
                
                <div class="tx-addresses">
                    ${tx.from ? `
                    <div class="address-row">
                        <span class="label">From:</span>
                        <span class="address">${truncateAddress(tx.from)}</span>
                    </div>
                    ` : ''}
                    ${tx.to ? `
                    <div class="address-row">
                        <span class="label">To:</span>
                        <span class="address">${truncateAddress(tx.to)}</span>
                    </div>
                    ` : ''}
                </div>
                
                <div class="tx-meta">
                    <div class="meta-item">
                        <span class="label">Time:</span>
                        <span class="value">${formatDate(tx.timestamp)}</span>
                    </div>
                    ${tx.hash ? `
                    <div class="meta-item">
                        <span class="label">Hash:</span>
                        <span class="value hash" title="${tx.hash}">${truncateAddress(tx.hash, 6)}</span>
                    </div>
                    ` : ''}
                    ${tx.blockNumber ? `
                    <div class="meta-item">
                        <span class="label">Block:</span>
                        <span class="value">#${tx.blockNumber}</span>
                    </div>
                    ` : ''}
                </div>
            </div>
            
            <div class="tx-actions">
                <button class="btn btn-sm btn-info" onclick="viewTransactionDetails('${tx.hash || tx.id}')">Details</button>
                ${tx.hash ? `<button class="btn btn-sm btn-secondary" onclick="copyTransactionHash('${tx.hash}')">Copy Hash</button>` : ''}
            </div>
        </div>
    `;
}

function getTransactionTypeClass(type) {
    switch (type?.toLowerCase()) {
        case 'transfer': return 'tx-transfer';
        case 'mint': return 'tx-mint';
        case 'burn': return 'tx-burn';
        case 'stake': return 'tx-stake';
        case 'unstake': return 'tx-unstake';
        case 'otc': return 'tx-otc';
        case 'escrow': return 'tx-escrow';
        default: return 'tx-unknown';
    }
}

function getTransactionStatusClass(status) {
    switch (status?.toLowerCase()) {
        case 'confirmed': return 'status-success';
        case 'pending': return 'status-pending';
        case 'failed': return 'status-error';
        default: return 'status-unknown';
    }
}

function getTransactionIcon(type) {
    switch (type?.toLowerCase()) {
        case 'transfer': return '💸';
        case 'mint': return '🪙';
        case 'burn': return '🔥';
        case 'stake': return '🔒';
        case 'unstake': return '🔓';
        case 'otc': return '🔄';
        case 'escrow': return '🛡️';
        default: return '📄';
    }
}

async function filterTransactions() {
    const addressFilter = document.getElementById('addressFilter').value.trim();
    
    if (!addressFilter) {
        loadTransactions(); // Load all transactions
        return;
    }
    
    const transactionsList = document.getElementById('transactionsList');
    transactionsList.innerHTML = '<p class="loading">Filtering transactions...</p>';
    
    try {
        const result = await apiCall(`/api/transactions?address=${addressFilter}&limit=50`);
        
        if (result.success) {
            const transactions = result.data || [];
            
            if (transactions.length === 0) {
                transactionsList.innerHTML = `
                    <div class="empty-state">
                        <p>No transactions found for address: ${truncateAddress(addressFilter)}</p>
                        <p class="text-muted">Try a different address or clear the filter</p>
                    </div>
                `;
            } else {
                transactionsList.innerHTML = `
                    <div class="transactions-list">
                        <div class="filter-info">
                            <p>Showing ${transactions.length} transactions for: ${truncateAddress(addressFilter)}</p>
                        </div>
                        ${transactions.map(tx => createTransactionCard(tx)).join('')}
                    </div>
                `;
            }
        } else {
            transactionsList.innerHTML = `<p class="error">Error filtering transactions: ${result.message}</p>`;
        }
    } catch (error) {
        transactionsList.innerHTML = `<p class="error">Error filtering transactions: ${error.message}</p>`;
        showAlert('Failed to filter transactions: ' + error.message, 'error');
    }
}

async function viewTransactionDetails(txId) {
    try {
        const result = await apiCall(`/api/transactions/${txId}`);
        
        if (result.success && result.data) {
            const tx = result.data;
            const content = `
                <div class="transaction-details-view">
                    <div class="detail-section">
                        <h4>Transaction Information</h4>
                        <div class="detail-grid">
                            <div class="detail-item">
                                <label>Type:</label>
                                <span>${tx.type}</span>
                            </div>
                            <div class="detail-item">
                                <label>Status:</label>
                                <span class="status ${getTransactionStatusClass(tx.status)}">${tx.status}</span>
                            </div>
                            <div class="detail-item">
                                <label>Amount:</label>
                                <span>${formatAmount(tx.amount)} BHX</span>
                            </div>
                            <div class="detail-item">
                                <label>Timestamp:</label>
                                <span>${formatDate(tx.timestamp)}</span>
                            </div>
                        </div>
                    </div>
                    
                    ${tx.from || tx.to ? `
                    <div class="detail-section">
                        <h4>Addresses</h4>
                        <div class="detail-grid">
                            ${tx.from ? `
                            <div class="detail-item">
                                <label>From:</label>
                                <span class="address">${tx.from}</span>
                            </div>
                            ` : ''}
                            ${tx.to ? `
                            <div class="detail-item">
                                <label>To:</label>
                                <span class="address">${tx.to}</span>
                            </div>
                            ` : ''}
                        </div>
                    </div>
                    ` : ''}
                    
                    ${tx.hash || tx.blockNumber ? `
                    <div class="detail-section">
                        <h4>Blockchain Information</h4>
                        <div class="detail-grid">
                            ${tx.hash ? `
                            <div class="detail-item">
                                <label>Hash:</label>
                                <span class="hash">${tx.hash}</span>
                            </div>
                            ` : ''}
                            ${tx.blockNumber ? `
                            <div class="detail-item">
                                <label>Block Number:</label>
                                <span>#${tx.blockNumber}</span>
                            </div>
                            ` : ''}
                        </div>
                    </div>
                    ` : ''}
                    
                    ${tx.note || tx.reason ? `
                    <div class="detail-section">
                        <h4>Additional Information</h4>
                        <p>${tx.note || tx.reason}</p>
                    </div>
                    ` : ''}
                </div>
            `;

            const actions = [];
            if (tx.hash) {
                actions.push({
                    text: 'Copy Hash',
                    class: 'btn-info',
                    onclick: `copyTransactionHash('${tx.hash}')`
                });
            }

            createModal(`Transaction Details - ${tx.type}`, content, actions);
        }
    } catch (error) {
        showAlert('Error loading transaction details: ' + error.message, 'error');
    }
}

function copyTransactionHash(hash) {
    navigator.clipboard.writeText(hash).then(() => {
        showAlert('Transaction hash copied to clipboard!', 'success');
    }).catch(() => {
        showAlert('Failed to copy transaction hash', 'error');
    });
}

// Enhanced Modal Styles
function addModalStyles() {
    if (document.getElementById('modal-styles')) return;
    
    const style = document.createElement('style');
    style.id = 'modal-styles';
    style.textContent = `
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(5px);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 1000;
        }
        
        .modal {
            background: white;
            border-radius: 16px;
            max-width: 600px;
            width: 90%;
            max-height: 90vh;
            overflow-y: auto;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }
        
        .modal-header {
            padding: 2rem 2rem 1rem;
            border-bottom: 1px solid #e2e8f0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .modal-header h3 {
            margin: 0;
            color: #4a5568;
        }
        
        .modal-close {
            background: none;
            border: none;
            font-size: 1.5rem;
            cursor: pointer;
            color: #718096;
            padding: 0;
            width: 30px;
            height: 30px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .modal-content {
            padding: 2rem;
        }
        
        .modal-actions {
            padding: 1rem 2rem 2rem;
            border-top: 1px solid #e2e8f0;
            display: flex;
            gap: 1rem;
            justify-content: flex-end;
        }
        
        .form-field {
            margin-bottom: 1.5rem;
        }
        
        .form-field label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: #4a5568;
        }
        
        .form-input {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s;
        }
        
        .form-input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .form-section {
            margin-bottom: 2rem;
            padding: 1rem;
            background: #f8f9fa;
            border-radius: 8px;
        }
        
        .form-section h4 {
            margin: 0 0 1rem 0;
            color: #4a5568;
        }
        
        .tabs {
            display: flex;
            border-bottom: 1px solid #e2e8f0;
            margin-bottom: 2rem;
        }
        
        .tab-button {
            padding: 1rem 1.5rem;
            border: none;
            background: none;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.3s;
        }
        
        .tab-button.active {
            border-bottom-color: #667eea;
            color: #667eea;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .warning-box {
            background: #fef5e7;
            border: 1px solid #f6ad55;
            border-radius: 8px;
            padding: 1rem;
            margin-top: 1rem;
        }
        
        .help-text {
            font-size: 0.8rem;
            color: #718096;
            margin-top: 0.25rem;
        }
    `;
    
    document.head.appendChild(style);
}

// Initialize modal styles when the script loads
addModalStyles();
