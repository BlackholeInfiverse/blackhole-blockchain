// Advanced Features Functions (Escrow & Staking)

function showEscrowModal() {
    const content = `
        <div class="tabs">
            <button class="tab-button active" onclick="switchAdvancedTab('create-escrow')">Create Escrow</button>
            <button class="tab-button" onclick="switchAdvancedTab('manage-escrow')">Manage Escrow</button>
        </div>
        
        <div id="create-escrow" class="tab-content active">
            <form id="escrowForm">
                ${createFormField('Buyer Address', 'text', 'buyer', 'Buyer address')}
                ${createFormField('Seller Address', 'text', 'seller', 'Seller address')}
                ${createFormField('Amount', 'number', 'amount', 'Escrow amount')}
                ${createFormField('Arbiter Address', 'text', 'arbiter', 'Arbiter address')}
                ${createFormField('Deadline (hours)', 'number', 'deadlineHours', 'Hours until deadline')}
                <div class="form-field">
                    <label for="escrowDescription">Description</label>
                    <textarea id="escrowDescription" placeholder="Escrow description" class="form-input"></textarea>
                </div>
            </form>
        </div>
        
        <div id="manage-escrow" class="tab-content">
            <div class="escrow-actions">
                <button class="btn btn-info" onclick="loadEscrowList()">Load Escrows</button>
                <button class="btn btn-success" onclick="showReleaseEscrowForm()">Release Escrow</button>
                <button class="btn btn-warning" onclick="showDisputeEscrowForm()">Dispute Escrow</button>
            </div>
            <div id="escrowList" class="content-area">
                <p class="text-muted">Click "Load Escrows" to view existing escrows</p>
            </div>
        </div>
    `;

    const actions = [
        {
            text: 'Create Escrow',
            class: 'btn-primary',
            onclick: 'submitEscrow()'
        }
    ];

    createModal('Escrow Services', content, actions);
}

function switchAdvancedTab(tabId) {
    // Remove active class from all tabs and contents
    document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    
    // Add active class to selected tab and content
    event.target.classList.add('active');
    document.getElementById(tabId).classList.add('active');
}

async function submitEscrow() {
    const form = document.getElementById('escrowForm');
    const formData = new FormData(form);
    
    const buyer = formData.get('buyer');
    const seller = formData.get('seller');
    const amount = parseInt(formData.get('amount'));
    const arbiter = formData.get('arbiter');
    const deadlineHours = parseInt(formData.get('deadlineHours'));
    const description = formData.get('escrowDescription');

    if (!buyer || !seller || !amount || !arbiter || !deadlineHours) {
        showAlert('All fields are required for escrow creation', 'error');
        return;
    }

    if (amount <= 0) {
        showAlert('Amount must be greater than 0', 'error');
        return;
    }

    try {
        const deadline = Date.now() + (deadlineHours * 60 * 60 * 1000);
        
        const result = await apiCall('/api/escrow/create', 'POST', {
            buyer,
            seller,
            amount,
            arbiter,
            deadline,
            description
        });

        if (result.success) {
            showAlert('Escrow created successfully!', 'success');
            loadEscrowList(); // Refresh escrow list if visible
        } else {
            showAlert('Failed to create escrow: ' + result.message, 'error');
        }
    } catch (error) {
        showAlert('Error creating escrow: ' + error.message, 'error');
    }
}

async function loadEscrowList() {
    const escrowList = document.getElementById('escrowList');
    escrowList.innerHTML = '<p class="loading">Loading escrows...</p>';
    
    try {
        const result = await apiCall('/api/escrow/list');
        
        if (result.success) {
            const escrows = result.data || [];
            
            if (escrows.length === 0) {
                escrowList.innerHTML = '<p class="text-muted">No escrows found</p>';
            } else {
                escrowList.innerHTML = `
                    <div class="escrow-list">
                        ${escrows.map(escrow => createEscrowCard(escrow)).join('')}
                    </div>
                `;
            }
        } else {
            escrowList.innerHTML = `<p class="error">Error loading escrows: ${result.message}</p>`;
        }
    } catch (error) {
        escrowList.innerHTML = `<p class="error">Error loading escrows: ${error.message}</p>`;
    }
}

function createEscrowCard(escrow) {
    const statusClass = getEscrowStatusClass(escrow.status);
    
    return `
        <div class="escrow-card ${statusClass}">
            <div class="escrow-header">
                <span class="escrow-id">Escrow #${escrow.id}</span>
                <span class="escrow-status ${statusClass}">${escrow.status}</span>
            </div>
            <div class="escrow-details">
                <div class="detail-row">
                    <span class="label">Amount:</span>
                    <span class="value">${formatAmount(escrow.amount)} BHX</span>
                </div>
                <div class="detail-row">
                    <span class="label">Buyer:</span>
                    <span class="value address">${truncateAddress(escrow.buyer)}</span>
                </div>
                <div class="detail-row">
                    <span class="label">Seller:</span>
                    <span class="value address">${truncateAddress(escrow.seller)}</span>
                </div>
                <div class="detail-row">
                    <span class="label">Deadline:</span>
                    <span class="value">${formatDate(escrow.deadline)}</span>
                </div>
            </div>
        </div>
    `;
}

function getEscrowStatusClass(status) {
    switch (status?.toLowerCase()) {
        case 'active': return 'status-active';
        case 'released': return 'status-completed';
        case 'disputed': return 'status-warning';
        case 'cancelled': return 'status-cancelled';
        default: return 'status-unknown';
    }
}

function showStakingModal() {
    const content = `
        <div class="tabs">
            <button class="tab-button active" onclick="switchAdvancedTab('stake-tokens')">Stake Tokens</button>
            <button class="tab-button" onclick="switchAdvancedTab('unstake-tokens')">Unstake Tokens</button>
            <button class="tab-button" onclick="switchAdvancedTab('staking-rewards')">View Rewards</button>
        </div>
        
        <div id="stake-tokens" class="tab-content active">
            <form id="stakeForm">
                ${createFormField('Staker Address', 'text', 'staker', 'Your address')}
                ${createFormField('Validator Address', 'text', 'validator', 'Validator address')}
                ${createFormField('Amount', 'number', 'stakeAmount', 'Amount to stake')}
            </form>
        </div>
        
        <div id="unstake-tokens" class="tab-content">
            <form id="unstakeForm">
                ${createFormField('Staker Address', 'text', 'unstaker', 'Your address')}
                ${createFormField('Validator Address', 'text', 'unstakeValidator', 'Validator address')}
                ${createFormField('Amount', 'number', 'unstakeAmount', 'Amount to unstake')}
            </form>
        </div>
        
        <div id="staking-rewards" class="tab-content">
            <form id="rewardsForm">
                ${createFormField('Staker Address', 'text', 'rewardsStaker', 'Staker address')}
            </form>
            <div id="rewardsResult" class="rewards-result" style="display: none;">
                <h4>Staking Rewards</h4>
                <div id="rewardsDetails"></div>
            </div>
        </div>
    `;

    const actions = [
        {
            text: 'Stake Tokens',
            class: 'btn-success',
            onclick: 'submitStake()'
        },
        {
            text: 'Unstake Tokens',
            class: 'btn-warning',
            onclick: 'submitUnstake()'
        },
        {
            text: 'Check Rewards',
            class: 'btn-info',
            onclick: 'submitRewardsCheck()'
        }
    ];

    createModal('Staking Services', content, actions);
}

async function submitStake() {
    const form = document.getElementById('stakeForm');
    const formData = new FormData(form);
    
    const staker = formData.get('staker');
    const validator = formData.get('validator');
    const amount = parseInt(formData.get('stakeAmount'));

    if (!staker || !validator || !amount) {
        showAlert('All fields are required for staking', 'error');
        return;
    }

    if (amount <= 0) {
        showAlert('Amount must be greater than 0', 'error');
        return;
    }

    try {
        const result = await apiCall('/api/staking/stake', 'POST', {
            staker,
            validator,
            amount
        });

        if (result.success) {
            showAlert('Stake successful!', 'success');
            loadTransactions(); // Refresh transaction list
        } else {
            showAlert('Stake failed: ' + result.message, 'error');
        }
    } catch (error) {
        showAlert('Error during stake: ' + error.message, 'error');
    }
}

async function submitUnstake() {
    const form = document.getElementById('unstakeForm');
    const formData = new FormData(form);
    
    const staker = formData.get('unstaker');
    const validator = formData.get('unstakeValidator');
    const amount = parseInt(formData.get('unstakeAmount'));

    if (!staker || !validator || !amount) {
        showAlert('All fields are required for unstaking', 'error');
        return;
    }

    if (amount <= 0) {
        showAlert('Amount must be greater than 0', 'error');
        return;
    }

    try {
        const result = await apiCall('/api/staking/unstake', 'POST', {
            staker,
            validator,
            amount
        });

        if (result.success) {
            showAlert('Unstake successful!', 'success');
            loadTransactions(); // Refresh transaction list
        } else {
            showAlert('Unstake failed: ' + result.message, 'error');
        }
    } catch (error) {
        showAlert('Error during unstake: ' + error.message, 'error');
    }
}

async function submitRewardsCheck() {
    const form = document.getElementById('rewardsForm');
    const formData = new FormData(form);
    const staker = formData.get('rewardsStaker');

    if (!staker) {
        showAlert('Staker address is required', 'error');
        return;
    }

    try {
        const result = await apiCall(`/api/staking/rewards?staker=${staker}`);
        
        if (result.success) {
            const rewardsResult = document.getElementById('rewardsResult');
            const rewardsDetails = document.getElementById('rewardsDetails');
            
            rewardsDetails.innerHTML = `
                <div class="rewards-display">
                    <div class="reward-item">
                        <span class="reward-label">Staker:</span>
                        <span class="reward-value address">${staker}</span>
                    </div>
                    <div class="reward-item">
                        <span class="reward-label">Total Rewards:</span>
                        <span class="reward-value amount">${formatAmount(result.data?.totalRewards || 0)} BHX</span>
                    </div>
                    <div class="reward-item">
                        <span class="reward-label">Pending Rewards:</span>
                        <span class="reward-value amount">${formatAmount(result.data?.pendingRewards || 0)} BHX</span>
                    </div>
                    <div class="reward-item">
                        <span class="reward-label">Last Updated:</span>
                        <span class="reward-value">${formatDate(Date.now())}</span>
                    </div>
                </div>
            `;
            
            rewardsResult.style.display = 'block';
            showAlert('Staking rewards retrieved successfully!', 'success');
        } else {
            showAlert('Failed to get staking rewards: ' + result.message, 'error');
        }
    } catch (error) {
        showAlert('Error getting staking rewards: ' + error.message, 'error');
    }
}

function showReleaseEscrowForm() {
    const content = `
        <form id="releaseEscrowForm">
            ${createFormField('Escrow ID', 'text', 'escrowId', 'Escrow ID to release')}
            ${createFormField('Releaser Address', 'text', 'releaser', 'Your address')}
        </form>
    `;

    const actions = [
        {
            text: 'Release Escrow',
            class: 'btn-success',
            onclick: 'submitReleaseEscrow()'
        }
    ];

    createModal('Release Escrow', content, actions);
}

async function submitReleaseEscrow() {
    const form = document.getElementById('releaseEscrowForm');
    const formData = new FormData(form);
    
    const escrowId = formData.get('escrowId');
    const releaser = formData.get('releaser');

    if (!escrowId || !releaser) {
        showAlert('Escrow ID and releaser address are required', 'error');
        return;
    }

    try {
        const result = await apiCall('/api/escrow/release', 'POST', {
            escrowId,
            releaser
        });

        if (result.success) {
            showAlert('Escrow released successfully!', 'success');
            closeModal(form.closest('.modal-overlay').id);
            loadEscrowList(); // Refresh escrow list
        } else {
            showAlert('Failed to release escrow: ' + result.message, 'error');
        }
    } catch (error) {
        showAlert('Error releasing escrow: ' + error.message, 'error');
    }
}

function showDisputeEscrowForm() {
    const content = `
        <form id="disputeEscrowForm">
            ${createFormField('Escrow ID', 'text', 'disputeEscrowId', 'Escrow ID to dispute')}
            ${createFormField('Disputer Address', 'text', 'disputer', 'Your address')}
            <div class="form-field">
                <label for="disputeReason">Reason for Dispute</label>
                <textarea id="disputeReason" placeholder="Explain the reason for dispute" class="form-input" required></textarea>
            </div>
        </form>
    `;

    const actions = [
        {
            text: 'Submit Dispute',
            class: 'btn-warning',
            onclick: 'submitDisputeEscrow()'
        }
    ];

    createModal('Dispute Escrow', content, actions);
}

async function submitDisputeEscrow() {
    const form = document.getElementById('disputeEscrowForm');
    const formData = new FormData(form);
    
    const escrowId = formData.get('disputeEscrowId');
    const disputer = formData.get('disputer');
    const reason = formData.get('disputeReason');

    if (!escrowId || !disputer || !reason) {
        showAlert('All fields are required for dispute', 'error');
        return;
    }

    try {
        const result = await apiCall('/api/escrow/dispute', 'POST', {
            escrowId,
            disputer,
            reason
        });

        if (result.success) {
            showAlert('Escrow dispute submitted successfully!', 'success');
            closeModal(form.closest('.modal-overlay').id);
            loadEscrowList(); // Refresh escrow list
        } else {
            showAlert('Failed to submit dispute: ' + result.message, 'error');
        }
    } catch (error) {
        showAlert('Error submitting dispute: ' + error.message, 'error');
    }
}
