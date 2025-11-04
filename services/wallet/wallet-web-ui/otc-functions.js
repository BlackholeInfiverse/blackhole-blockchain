// OTC Trading Functions

async function loadOTCOrders() {
    const otcOrdersList = document.getElementById('otcOrdersList');
    otcOrdersList.innerHTML = '<p class="loading">Loading OTC orders...</p>';
    
    try {
        const result = await apiCall('/api/otc/orders');
        
        if (result.success) {
            const orders = result.data || [];
            
            if (orders.length === 0) {
                otcOrdersList.innerHTML = `
                    <div class="empty-state">
                        <p>No OTC orders found</p>
                        <p class="text-muted">Create your first OTC order to start trading!</p>
                    </div>
                `;
            } else {
                otcOrdersList.innerHTML = `
                    <div class="otc-orders-list">
                        ${orders.map(order => createOTCOrderCard(order)).join('')}
                    </div>
                `;
            }
            showAlert('OTC orders loaded successfully!', 'success');
        } else {
            otcOrdersList.innerHTML = `<p class="error">Error loading OTC orders: ${result.message}</p>`;
        }
    } catch (error) {
        otcOrdersList.innerHTML = `<p class="error">Error loading OTC orders: ${error.message}</p>`;
        showAlert('Failed to load OTC orders: ' + error.message, 'error');
    }
}

function createOTCOrderCard(order) {
    const statusClass = getOrderStatusClass(order.status);
    const isExpired = order.expirationTime && Date.now() > order.expirationTime;
    
    return `
        <div class="otc-order-card ${statusClass}">
            <div class="order-header">
                <span class="order-id">Order #${order.id || 'Unknown'}</span>
                <span class="order-status ${statusClass}">${order.status || 'Unknown'}</span>
            </div>
            
            <div class="order-details">
                <div class="trade-info">
                    <div class="offered">
                        <span class="label">Offering:</span>
                        <span class="amount">${formatAmount(order.amountOffered || 0)} ${order.tokenOffered || 'BHX'}</span>
                    </div>
                    <div class="exchange-icon">⇄</div>
                    <div class="requested">
                        <span class="label">Requesting:</span>
                        <span class="amount">${formatAmount(order.amountRequested || 0)} ${order.tokenRequested || 'BHX'}</span>
                    </div>
                </div>
                
                <div class="order-meta">
                    <div class="meta-item">
                        <span class="label">Creator:</span>
                        <span class="value address">${truncateAddress(order.creator)}</span>
                    </div>
                    <div class="meta-item">
                        <span class="label">Created:</span>
                        <span class="value">${formatDate(order.createdAt)}</span>
                    </div>
                    ${order.expirationTime ? `
                    <div class="meta-item">
                        <span class="label">Expires:</span>
                        <span class="value ${isExpired ? 'expired' : ''}">${formatDate(order.expirationTime)}</span>
                    </div>
                    ` : ''}
                    ${order.multiSig ? `
                    <div class="meta-item">
                        <span class="label">Multi-Sig:</span>
                        <span class="value">✓ Enabled</span>
                    </div>
                    ` : ''}
                </div>
            </div>
            
            <div class="order-actions">
                ${getOrderActions(order)}
            </div>
        </div>
    `;
}

function getOrderStatusClass(status) {
    switch (status?.toLowerCase()) {
        case 'active': return 'status-active';
        case 'matched': return 'status-matched';
        case 'completed': return 'status-completed';
        case 'cancelled': return 'status-cancelled';
        case 'expired': return 'status-expired';
        default: return 'status-unknown';
    }
}

function getOrderActions(order) {
    const actions = [];
    const currentUser = app?.user?.address;

    if (order.status === 'active' || order.status === 'open') {
        // Show different buttons based on whether user is the creator
        if (order.creator === currentUser) {
            // Creator can cancel their own order
            actions.push(`<button class="btn btn-sm btn-warning" onclick="cancelOTCOrder('${order.id}')">Cancel Order</button>`);
        } else {
            // Other users can accept the order
            actions.push(`<button class="btn btn-sm btn-success" onclick="acceptOTCOrder('${order.id}')">Accept Order</button>`);
        }
    }

    if (order.status === 'matched' && order.multiSig) {
        actions.push(`<button class="btn btn-sm btn-success" onclick="signOTCOrder('${order.id}')">Sign</button>`);
    }

    actions.push(`<button class="btn btn-sm btn-info" onclick="viewOTCOrderDetails('${order.id}')">Details</button>`);

    return actions.join('');
}

function showOTCModal() {
    const content = `
        <form id="otcForm">
            ${createFormField('Creator Address', 'text', 'creator', 'Your address')}
            
            <div class="form-section">
                <h4>Offering</h4>
                ${createFormField('Token Offered', 'text', 'tokenOffered', 'e.g., BHX')}
                ${createFormField('Amount Offered', 'number', 'amountOffered', 'Amount you are offering')}
            </div>
            
            <div class="form-section">
                <h4>Requesting</h4>
                ${createFormField('Token Requested', 'text', 'tokenRequested', 'e.g., ETH')}
                ${createFormField('Amount Requested', 'number', 'amountRequested', 'Amount you want in return')}
            </div>
            
            <div class="form-section">
                <h4>Order Settings</h4>
                ${createFormField('Expiration (hours)', 'number', 'expirationHours', 'Hours until expiration', false)}
                <div class="form-field">
                    <label>
                        <input type="checkbox" id="multiSig"> Enable Multi-Signature
                    </label>
                    <small class="help-text">Requires multiple signatures to complete the trade</small>
                </div>
            </div>
        </form>
    `;

    const actions = [
        {
            text: 'Create OTC Order',
            class: 'btn-primary',
            onclick: 'submitOTCOrder()'
        }
    ];

    createModal('Create OTC Order', content, actions);
}

async function submitOTCOrder() {
    const form = document.getElementById('otcForm');
    const formData = new FormData(form);
    
    const creator = formData.get('creator');
    const tokenOffered = formData.get('tokenOffered');
    const amountOffered = parseInt(formData.get('amountOffered'));
    const tokenRequested = formData.get('tokenRequested');
    const amountRequested = parseInt(formData.get('amountRequested'));
    const expirationHours = formData.get('expirationHours');
    const multiSig = formData.get('multiSig') === 'on';

    // Validation
    if (!creator || !tokenOffered || !amountOffered || !tokenRequested || !amountRequested) {
        showAlert('All required fields must be filled', 'error');
        return;
    }

    if (amountOffered <= 0 || amountRequested <= 0) {
        showAlert('Amounts must be greater than 0', 'error');
        return;
    }

    try {
        const data = {
            creator,
            tokenOffered,
            amountOffered,
            tokenRequested,
            amountRequested,
            multiSig
        };

        if (expirationHours) {
            data.expirationTime = Date.now() + (parseInt(expirationHours) * 60 * 60 * 1000);
        }

        const result = await apiCall('/api/otc/create', 'POST', data);

        if (result.success) {
            showAlert('OTC order created successfully!', 'success');
            closeModal(form.closest('.modal-overlay').id);
            loadOTCOrders(); // Refresh OTC orders list
        } else {
            showAlert('Failed to create OTC order: ' + result.message, 'error');
        }
    } catch (error) {
        showAlert('Error creating OTC order: ' + error.message, 'error');
    }
}

async function acceptOTCOrder(orderId) {
    try {
        // Get current user's address
        const currentUser = app?.user?.address;
        if (!currentUser) {
            showAlert('Please login to accept orders', 'error');
            return;
        }

        // Find the order details
        const orders = await getOTCOrders();
        const order = orders.find(o => o.order_id === orderId || o.id === orderId);

        if (!order) {
            showAlert('Order not found', 'error');
            return;
        }

        // Show confirmation modal with order details
        const confirmed = await showAcceptOrderModal(order, currentUser);
        if (!confirmed) return;

        // Check if user has sufficient balance
        const hasBalance = await checkUserBalance(currentUser, order.token_requested, order.amount_requested);
        if (!hasBalance) {
            showAlert(`Insufficient ${order.token_requested} balance. You need ${order.amount_requested} ${order.token_requested} to accept this order.`, 'error');
            return;
        }

        // Get current wallet info for the API call
        const currentWallet = app?.currentWallet;
        if (!currentWallet) {
            showAlert('Please select a wallet first', 'error');
            return;
        }

        // Prompt for password (required by API)
        const password = prompt('Enter your wallet password to accept this order:');
        if (!password) return;

        // Accept the order
        const result = await apiCall('/api/otc/match', 'POST', {
            order_id: orderId,
            wallet_name: currentWallet.name,
            password: password
        });

        if (result.success) {
            showAlert('🎉 Order accepted successfully! Tokens have been exchanged.', 'success');
            loadOTCOrders(); // Refresh orders
        } else {
            showAlert('Failed to accept order: ' + result.message, 'error');
        }
    } catch (error) {
        showAlert('Error accepting order: ' + error.message, 'error');
    }
}

// Keep the old function for backward compatibility
async function matchOTCOrder(orderId) {
    return acceptOTCOrder(orderId);
}

// Helper function to show order acceptance confirmation modal
async function showAcceptOrderModal(order, userAddress) {
    return new Promise((resolve) => {
        const modal = document.createElement('div');
        modal.className = 'modal-overlay';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3>🤝 Accept OTC Order</h3>
                    <button class="modal-close" onclick="this.closest('.modal-overlay').remove(); resolve(false);">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="order-summary">
                        <h4>Order Details:</h4>
                        <div class="trade-preview">
                            <div class="trade-side">
                                <strong>You Give:</strong><br>
                                <span class="amount">${order.amount_requested} ${order.token_requested}</span>
                            </div>
                            <div class="trade-arrow">⇄</div>
                            <div class="trade-side">
                                <strong>You Get:</strong><br>
                                <span class="amount">${order.amount_offered} ${order.token_offered}</span>
                            </div>
                        </div>
                        <div class="order-info">
                            <p><strong>Order Creator:</strong> ${order.creator}</p>
                            <p><strong>Your Address:</strong> ${userAddress}</p>
                            <p><strong>Expires:</strong> ${new Date(order.expiration * 1000).toLocaleString()}</p>
                        </div>
                    </div>
                    <div class="warning-box">
                        <p>⚠️ <strong>Important:</strong> This action will immediately exchange your tokens. Make sure you have sufficient balance.</p>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" onclick="this.closest('.modal-overlay').remove();">Cancel</button>
                    <button class="btn btn-success" onclick="this.closest('.modal-overlay').remove(); resolve(true);">Accept Order</button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        // Add click handlers
        modal.querySelector('.btn-secondary').onclick = () => {
            modal.remove();
            resolve(false);
        };

        modal.querySelector('.btn-success').onclick = () => {
            modal.remove();
            resolve(true);
        };

        modal.onclick = (e) => {
            if (e.target === modal) {
                modal.remove();
                resolve(false);
            }
        };
    });
}

// Helper function to check user balance
async function checkUserBalance(address, tokenSymbol, requiredAmount) {
    try {
        const result = await apiCall(`/api/wallets/balance?address=${address}&token=${tokenSymbol}`, 'GET');
        if (result.success && result.data) {
            const balance = result.data.balance || 0;
            return balance >= requiredAmount;
        }
        return false;
    } catch (error) {
        console.error('Error checking balance:', error);
        return false;
    }
}

async function cancelOTCOrder(orderId) {
    if (!confirm('Are you sure you want to cancel this OTC order?')) return;

    const creator = prompt('Enter your address to confirm cancellation:');
    if (!creator) return;

    try {
        const result = await apiCall('/api/otc/cancel', 'POST', {
            orderId: orderId,
            creator: creator
        });

        if (result.success) {
            showAlert('OTC order cancelled successfully!', 'success');
            loadOTCOrders(); // Refresh orders
        } else {
            showAlert('Failed to cancel OTC order: ' + result.message, 'error');
        }
    } catch (error) {
        showAlert('Error cancelling OTC order: ' + error.message, 'error');
    }
}

async function signOTCOrder(orderId) {
    const signer = prompt('Enter your address:');
    if (!signer) return;

    const signature = prompt('Enter your signature:');
    if (!signature) return;

    try {
        const result = await apiCall('/api/otc/sign', 'POST', {
            orderId: orderId,
            signer: signer,
            signature: signature
        });

        if (result.success) {
            showAlert('OTC order signed successfully!', 'success');
            loadOTCOrders(); // Refresh orders
        } else {
            showAlert('Failed to sign OTC order: ' + result.message, 'error');
        }
    } catch (error) {
        showAlert('Error signing OTC order: ' + error.message, 'error');
    }
}

async function viewOTCOrderDetails(orderId) {
    try {
        const result = await apiCall(`/api/otc/orders/${orderId}`);
        
        if (result.success && result.data) {
            const order = result.data;
            const content = `
                <div class="order-details-view">
                    <div class="detail-section">
                        <h4>Order Information</h4>
                        <div class="detail-grid">
                            <div class="detail-item">
                                <label>Order ID:</label>
                                <span>${order.id}</span>
                            </div>
                            <div class="detail-item">
                                <label>Status:</label>
                                <span class="status ${getOrderStatusClass(order.status)}">${order.status}</span>
                            </div>
                            <div class="detail-item">
                                <label>Creator:</label>
                                <span class="address">${order.creator}</span>
                            </div>
                        </div>
                    </div>
                    
                    <div class="detail-section">
                        <h4>Trade Details</h4>
                        <div class="trade-details">
                            <div class="trade-side">
                                <h5>Offering</h5>
                                <p>${formatAmount(order.amountOffered)} ${order.tokenOffered}</p>
                            </div>
                            <div class="trade-side">
                                <h5>Requesting</h5>
                                <p>${formatAmount(order.amountRequested)} ${order.tokenRequested}</p>
                            </div>
                        </div>
                    </div>
                    
                    ${order.expirationTime ? `
                    <div class="detail-section">
                        <h4>Expiration</h4>
                        <p>${formatDate(order.expirationTime)}</p>
                    </div>
                    ` : ''}
                    
                    ${order.multiSig ? `
                    <div class="detail-section">
                        <h4>Multi-Signature</h4>
                        <p>✓ Multi-signature enabled for this order</p>
                    </div>
                    ` : ''}
                </div>
            `;

            createModal(`OTC Order Details - #${order.id}`, content, []);
        }
    } catch (error) {
        showAlert('Error loading order details: ' + error.message, 'error');
    }
}

async function loadOTCEvents() {
    try {
        const result = await apiCall('/api/otc/events');
        
        if (result.success) {
            const events = result.data || [];
            
            const content = `
                <div class="events-list">
                    ${events.length === 0 ? 
                        '<p class="text-muted">No recent OTC events found</p>' :
                        events.map(event => `
                            <div class="event-item">
                                <div class="event-type">${event.type}</div>
                                <div class="event-details">${event.details}</div>
                                <div class="event-time">${formatDate(event.timestamp)}</div>
                            </div>
                        `).join('')
                    }
                </div>
            `;

            createModal('Recent OTC Events', content, []);
            showAlert('OTC events loaded successfully!', 'success');
        } else {
            showAlert('Failed to load OTC events: ' + result.message, 'error');
        }
    } catch (error) {
        showAlert('Error loading OTC events: ' + error.message, 'error');
    }
}
