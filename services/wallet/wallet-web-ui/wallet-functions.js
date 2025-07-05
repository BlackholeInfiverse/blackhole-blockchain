// Wallet Management Functions

async function loadWallets() {
    const walletsList = document.getElementById('walletsList');
    walletsList.innerHTML = '<p class="loading">Loading wallets...</p>';
    
    try {
        const result = await apiCall('/api/wallets');
        
        if (result.success && result.data) {
            const wallets = result.data;
            
            if (wallets.length === 0) {
                walletsList.innerHTML = `
                    <div class="empty-state">
                        <p>No wallets found</p>
                        <p class="text-muted">Create your first wallet to get started!</p>
                    </div>
                `;
            } else {
                walletsList.innerHTML = `
                    <div class="wallets-grid">
                        ${wallets.map(wallet => createWalletCard(wallet)).join('')}
                    </div>
                `;
            }
        } else {
            walletsList.innerHTML = `<p class="error">Error loading wallets: ${result.message}</p>`;
        }
    } catch (error) {
        walletsList.innerHTML = `<p class="error">Error loading wallets: ${error.message}</p>`;
        showAlert('Failed to load wallets: ' + error.message, 'error');
    }
}

function createWalletCard(wallet) {
    return `
        <div class="wallet-card">
            <div class="wallet-header">
                <h4>${wallet.name || 'Unnamed Wallet'}</h4>
                <span class="wallet-type">${wallet.type || 'Standard'}</span>
            </div>
            <div class="wallet-details">
                <div class="detail-row">
                    <span class="label">Address:</span>
                    <span class="value address" title="${wallet.address}">${truncateAddress(wallet.address)}</span>
                </div>
                <div class="detail-row">
                    <span class="label">Created:</span>
                    <span class="value">${formatDate(wallet.createdAt)}</span>
                </div>
                ${wallet.balance !== undefined ? `
                <div class="detail-row">
                    <span class="label">Balance:</span>
                    <span class="value">${formatAmount(wallet.balance)} BHX</span>
                </div>
                ` : ''}
            </div>
            <div class="wallet-actions">
                <button class="btn btn-sm btn-primary" onclick="viewWalletDetails('${wallet.id}')">Details</button>
                <button class="btn btn-sm btn-info" onclick="copyAddress('${wallet.address}')">Copy Address</button>
                <button class="btn btn-sm btn-warning" onclick="exportWallet('${wallet.id}')">Export</button>
            </div>
        </div>
    `;
}

function createWallet() {
    const content = `
        <form id="createWalletForm">
            ${createFormField('Wallet Name', 'text', 'walletName', 'Enter wallet name')}
            ${createFormField('Password', 'password', 'password', 'Enter password for encryption')}
            ${createFormField('Confirm Password', 'password', 'confirmPassword', 'Confirm password')}
            <div class="form-field">
                <label>
                    <input type="checkbox" id="generateMnemonic" checked> Generate new mnemonic phrase
                </label>
            </div>
            <div class="form-field" id="mnemonicField" style="display: none;">
                ${createFormField('Mnemonic Phrase', 'text', 'mnemonic', 'Enter existing mnemonic phrase', false)}
            </div>
        </form>
    `;

    const actions = [
        {
            text: 'Create Wallet',
            class: 'btn-primary',
            onclick: 'submitCreateWallet()'
        }
    ];

    const modalId = createModal('Create New Wallet', content, actions);

    // Add event listener for mnemonic checkbox
    document.getElementById('generateMnemonic').addEventListener('change', function() {
        const mnemonicField = document.getElementById('mnemonicField');
        mnemonicField.style.display = this.checked ? 'none' : 'block';
    });
}

async function submitCreateWallet() {
    const form = document.getElementById('createWalletForm');
    const formData = new FormData(form);
    
    const walletName = formData.get('walletName');
    const password = formData.get('password');
    const confirmPassword = formData.get('confirmPassword');
    const generateMnemonic = formData.get('generateMnemonic') === 'on';
    const mnemonic = formData.get('mnemonic');

    // Validation
    if (!walletName || !password) {
        showAlert('Wallet name and password are required', 'error');
        return;
    }

    if (password !== confirmPassword) {
        showAlert('Passwords do not match', 'error');
        return;
    }

    if (!generateMnemonic && !mnemonic) {
        showAlert('Please provide a mnemonic phrase or enable generation', 'error');
        return;
    }

    try {
        const data = {
            walletName,
            password
        };

        if (!generateMnemonic) {
            data.mnemonic = mnemonic;
        }

        const result = await apiCall('/api/create-wallet', 'POST', data);
        
        if (result.success) {
            showAlert('Wallet created successfully!', 'success');
            closeModal(form.closest('.modal-overlay').id);
            loadWallets(); // Refresh wallet list
            
            // Show mnemonic if generated
            if (result.data && result.data.mnemonic) {
                showMnemonicModal(result.data.mnemonic);
            }
        } else {
            showAlert('Failed to create wallet: ' + result.message, 'error');
        }
    } catch (error) {
        showAlert('Error creating wallet: ' + error.message, 'error');
    }
}

function showMnemonicModal(mnemonic) {
    const content = `
        <div class="mnemonic-display">
            <p class="warning">⚠️ <strong>Important:</strong> Save this mnemonic phrase securely. You'll need it to recover your wallet.</p>
            <div class="mnemonic-phrase">
                ${mnemonic}
            </div>
            <p class="text-muted">Write this down and store it in a safe place. Do not share it with anyone.</p>
        </div>
    `;

    const actions = [
        {
            text: 'I have saved it securely',
            class: 'btn-primary',
            onclick: 'closeModal(this.closest(".modal-overlay").id)'
        }
    ];

    createModal('Your Wallet Mnemonic', content, actions);
}

async function viewWalletDetails(walletId) {
    try {
        const result = await apiCall(`/api/wallets/${walletId}`);
        
        if (result.success && result.data) {
            const wallet = result.data;
            const content = `
                <div class="wallet-details-view">
                    <div class="detail-section">
                        <h4>Basic Information</h4>
                        <div class="detail-grid">
                            <div class="detail-item">
                                <label>Name:</label>
                                <span>${wallet.name}</span>
                            </div>
                            <div class="detail-item">
                                <label>Address:</label>
                                <span class="address">${wallet.address}</span>
                            </div>
                            <div class="detail-item">
                                <label>Created:</label>
                                <span>${formatDate(wallet.createdAt)}</span>
                            </div>
                        </div>
                    </div>
                    
                    <div class="detail-section">
                        <h4>Balance Information</h4>
                        <div class="balance-info">
                            <div class="balance-item">
                                <span class="balance-label">BHX Balance:</span>
                                <span class="balance-value">${formatAmount(wallet.balance || 0)}</span>
                            </div>
                        </div>
                    </div>
                </div>
            `;

            const actions = [
                {
                    text: 'Copy Address',
                    class: 'btn-info',
                    onclick: `copyAddress('${wallet.address}')`
                },
                {
                    text: 'Export Wallet',
                    class: 'btn-warning',
                    onclick: `exportWallet('${wallet.id}')`
                }
            ];

            createModal(`Wallet Details - ${wallet.name}`, content, actions);
        }
    } catch (error) {
        showAlert('Error loading wallet details: ' + error.message, 'error');
    }
}

function copyAddress(address) {
    navigator.clipboard.writeText(address).then(() => {
        showAlert('Address copied to clipboard!', 'success');
    }).catch(() => {
        showAlert('Failed to copy address', 'error');
    });
}

async function exportWallet(walletId) {
    const password = prompt('Enter your wallet password to export:');
    if (!password) return;

    try {
        const result = await apiCall('/api/export-wallet', 'POST', {
            walletId,
            password
        });

        if (result.success) {
            // Create download link for wallet file
            const blob = new Blob([JSON.stringify(result.data, null, 2)], {
                type: 'application/json'
            });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `wallet-${walletId}.json`;
            a.click();
            URL.revokeObjectURL(url);
            
            showAlert('Wallet exported successfully!', 'success');
        }
    } catch (error) {
        showAlert('Error exporting wallet: ' + error.message, 'error');
    }
}
