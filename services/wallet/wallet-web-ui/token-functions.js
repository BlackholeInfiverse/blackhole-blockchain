// Token Operations Functions

function showTransferModal() {
    const content = `
        <form id="transferForm">
            ${createFormField('From Address', 'text', 'fromAddress', 'Sender address')}
            ${createFormField('To Address', 'text', 'toAddress', 'Recipient address')}
            ${createFormField('Amount', 'number', 'amount', 'Amount to transfer', true)}
            <div class="form-field">
                <label for="transferNote">Note (optional)</label>
                <textarea id="transferNote" placeholder="Transaction note" class="form-input"></textarea>
            </div>
        </form>
    `;

    const actions = [
        {
            text: 'Transfer Tokens',
            class: 'btn-primary',
            onclick: 'submitTransfer()'
        }
    ];

    createModal('Transfer Tokens', content, actions);
}

async function submitTransfer() {
    const form = document.getElementById('transferForm');
    const formData = new FormData(form);
    
    const fromAddress = formData.get('fromAddress');
    const toAddress = formData.get('toAddress');
    const amount = parseInt(formData.get('amount'));
    const note = formData.get('transferNote');

    if (!fromAddress || !toAddress || !amount) {
        showAlert('All fields are required for transfer', 'error');
        return;
    }

    if (amount <= 0) {
        showAlert('Amount must be greater than 0', 'error');
        return;
    }

    try {
        const result = await apiCall('/api/transfer', 'POST', {
            from: fromAddress,
            to: toAddress,
            amount: amount,
            note: note
        });

        if (result.success) {
            showAlert('Transfer successful!', 'success');
            closeModal(form.closest('.modal-overlay').id);
            loadTransactions(); // Refresh transaction list
            loadWallets(); // Refresh wallet balances
        } else {
            showAlert('Transfer failed: ' + result.message, 'error');
        }
    } catch (error) {
        showAlert('Error during transfer: ' + error.message, 'error');
    }
}

function showMintModal() {
    const content = `
        <form id="mintForm">
            ${createFormField('To Address', 'text', 'toAddress', 'Address to mint tokens to')}
            ${createFormField('Amount', 'number', 'amount', 'Amount to mint')}
            <div class="form-field">
                <label for="mintReason">Reason (optional)</label>
                <textarea id="mintReason" placeholder="Reason for minting" class="form-input"></textarea>
            </div>
            <div class="warning-box">
                <p>⚠️ <strong>Warning:</strong> Minting tokens increases the total supply. Only authorized users can mint tokens.</p>
            </div>
        </form>
    `;

    const actions = [
        {
            text: 'Mint Tokens',
            class: 'btn-success',
            onclick: 'submitMint()'
        }
    ];

    createModal('Mint Tokens', content, actions);
}

async function submitMint() {
    const form = document.getElementById('mintForm');
    const formData = new FormData(form);
    
    const toAddress = formData.get('toAddress');
    const amount = parseInt(formData.get('amount'));
    const reason = formData.get('mintReason');

    if (!toAddress || !amount) {
        showAlert('Address and amount are required for minting', 'error');
        return;
    }

    if (amount <= 0) {
        showAlert('Amount must be greater than 0', 'error');
        return;
    }

    try {
        const result = await apiCall('/api/mint', 'POST', {
            to: toAddress,
            amount: amount,
            reason: reason
        });

        if (result.success) {
            showAlert('Mint successful!', 'success');
            closeModal(form.closest('.modal-overlay').id);
            loadTransactions(); // Refresh transaction list
            loadWallets(); // Refresh wallet balances
        } else {
            showAlert('Mint failed: ' + result.message, 'error');
        }
    } catch (error) {
        showAlert('Error during mint: ' + error.message, 'error');
    }
}

function showBurnModal() {
    const content = `
        <form id="burnForm">
            ${createFormField('From Address', 'text', 'fromAddress', 'Address to burn tokens from')}
            ${createFormField('Amount', 'number', 'amount', 'Amount to burn')}
            <div class="form-field">
                <label for="burnReason">Reason (optional)</label>
                <textarea id="burnReason" placeholder="Reason for burning" class="form-input"></textarea>
            </div>
            <div class="warning-box">
                <p>⚠️ <strong>Warning:</strong> Burning tokens permanently removes them from circulation. This action cannot be undone.</p>
            </div>
        </form>
    `;

    const actions = [
        {
            text: 'Burn Tokens',
            class: 'btn-warning',
            onclick: 'submitBurn()'
        }
    ];

    createModal('Burn Tokens', content, actions);
}

async function submitBurn() {
    const form = document.getElementById('burnForm');
    const formData = new FormData(form);
    
    const fromAddress = formData.get('fromAddress');
    const amount = parseInt(formData.get('amount'));
    const reason = formData.get('burnReason');

    if (!fromAddress || !amount) {
        showAlert('Address and amount are required for burning', 'error');
        return;
    }

    if (amount <= 0) {
        showAlert('Amount must be greater than 0', 'error');
        return;
    }

    try {
        const result = await apiCall('/api/burn', 'POST', {
            from: fromAddress,
            amount: amount,
            reason: reason
        });

        if (result.success) {
            showAlert('Burn successful!', 'success');
            closeModal(form.closest('.modal-overlay').id);
            loadTransactions(); // Refresh transaction list
            loadWallets(); // Refresh wallet balances
        } else {
            showAlert('Burn failed: ' + result.message, 'error');
        }
    } catch (error) {
        showAlert('Error during burn: ' + error.message, 'error');
    }
}

function checkBalance() {
    const content = `
        <form id="balanceForm">
            ${createFormField('Address', 'text', 'address', 'Address to check balance')}
        </form>
        <div id="balanceResult" class="balance-result" style="display: none;">
            <h4>Balance Information</h4>
            <div id="balanceDetails"></div>
        </div>
    `;

    const actions = [
        {
            text: 'Check Balance',
            class: 'btn-info',
            onclick: 'submitBalanceCheck()'
        }
    ];

    createModal('Check Balance', content, actions);
}

async function submitBalanceCheck() {
    const form = document.getElementById('balanceForm');
    const formData = new FormData(form);
    const address = formData.get('address');

    if (!address) {
        showAlert('Address is required for balance check', 'error');
        return;
    }

    try {
        const result = await apiCall(`/api/check-balance?address=${address}`);
        
        if (result.success) {
            const balanceResult = document.getElementById('balanceResult');
            const balanceDetails = document.getElementById('balanceDetails');
            
            balanceDetails.innerHTML = `
                <div class="balance-display">
                    <div class="balance-item">
                        <span class="balance-label">Address:</span>
                        <span class="balance-value address">${address}</span>
                    </div>
                    <div class="balance-item">
                        <span class="balance-label">BHX Balance:</span>
                        <span class="balance-value amount">${formatAmount(result.data?.balance || 0)}</span>
                    </div>
                    <div class="balance-item">
                        <span class="balance-label">Last Updated:</span>
                        <span class="balance-value">${formatDate(Date.now())}</span>
                    </div>
                </div>
            `;
            
            balanceResult.style.display = 'block';
            showAlert('Balance retrieved successfully!', 'success');
        } else {
            showAlert('Failed to get balance: ' + result.message, 'error');
        }
    } catch (error) {
        showAlert('Error getting balance: ' + error.message, 'error');
    }
}

function showAllowanceModal() {
    const content = `
        <div class="tabs">
            <button class="tab-button active" onclick="switchTab('check-allowance')">Check Allowance</button>
            <button class="tab-button" onclick="switchTab('set-allowance')">Set Allowance</button>
        </div>
        
        <div id="check-allowance" class="tab-content active">
            <form id="checkAllowanceForm">
                ${createFormField('Owner Address', 'text', 'ownerAddress', 'Token owner address')}
                ${createFormField('Spender Address', 'text', 'spenderAddress', 'Spender address')}
            </form>
            <div id="allowanceResult" class="allowance-result" style="display: none;">
                <h4>Allowance Information</h4>
                <div id="allowanceDetails"></div>
            </div>
        </div>
        
        <div id="set-allowance" class="tab-content">
            <form id="setAllowanceForm">
                ${createFormField('Owner Address', 'text', 'setOwnerAddress', 'Token owner address')}
                ${createFormField('Spender Address', 'text', 'setSpenderAddress', 'Spender address')}
                ${createFormField('Amount', 'number', 'allowanceAmount', 'Allowance amount')}
            </form>
        </div>
    `;

    const actions = [
        {
            text: 'Check Allowance',
            class: 'btn-info',
            onclick: 'submitAllowanceCheck()'
        },
        {
            text: 'Set Allowance',
            class: 'btn-primary',
            onclick: 'submitAllowanceSet()'
        }
    ];

    createModal('Manage Allowances', content, actions);
}

function switchTab(tabId) {
    // Remove active class from all tabs and contents
    document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    
    // Add active class to selected tab and content
    event.target.classList.add('active');
    document.getElementById(tabId).classList.add('active');
}

async function submitAllowanceCheck() {
    const form = document.getElementById('checkAllowanceForm');
    const formData = new FormData(form);
    
    const owner = formData.get('ownerAddress');
    const spender = formData.get('spenderAddress');

    if (!owner || !spender) {
        showAlert('Owner and spender addresses are required', 'error');
        return;
    }

    try {
        const result = await apiCall(`/api/allowance?owner=${owner}&spender=${spender}`);
        
        if (result.success) {
            const allowanceResult = document.getElementById('allowanceResult');
            const allowanceDetails = document.getElementById('allowanceDetails');
            
            allowanceDetails.innerHTML = `
                <div class="allowance-display">
                    <div class="allowance-item">
                        <span class="allowance-label">Owner:</span>
                        <span class="allowance-value address">${owner}</span>
                    </div>
                    <div class="allowance-item">
                        <span class="allowance-label">Spender:</span>
                        <span class="allowance-value address">${spender}</span>
                    </div>
                    <div class="allowance-item">
                        <span class="allowance-label">Allowance:</span>
                        <span class="allowance-value amount">${formatAmount(result.data?.allowance || 0)}</span>
                    </div>
                </div>
            `;
            
            allowanceResult.style.display = 'block';
            showAlert('Allowance retrieved successfully!', 'success');
        } else {
            showAlert('Failed to get allowance: ' + result.message, 'error');
        }
    } catch (error) {
        showAlert('Error getting allowance: ' + error.message, 'error');
    }
}

async function submitAllowanceSet() {
    const form = document.getElementById('setAllowanceForm');
    const formData = new FormData(form);
    
    const owner = formData.get('setOwnerAddress');
    const spender = formData.get('setSpenderAddress');
    const amount = parseInt(formData.get('allowanceAmount'));

    if (!owner || !spender || amount === undefined) {
        showAlert('All fields are required for setting allowance', 'error');
        return;
    }

    if (amount < 0) {
        showAlert('Amount cannot be negative', 'error');
        return;
    }

    try {
        const result = await apiCall('/api/allowance', 'POST', {
            owner: owner,
            spender: spender,
            amount: amount
        });

        if (result.success) {
            showAlert('Allowance set successfully!', 'success');
            // Optionally refresh the check tab
            if (document.getElementById('check-allowance').classList.contains('active')) {
                submitAllowanceCheck();
            }
        } else {
            showAlert('Failed to set allowance: ' + result.message, 'error');
        }
    } catch (error) {
        showAlert('Error setting allowance: ' + error.message, 'error');
    }
}
