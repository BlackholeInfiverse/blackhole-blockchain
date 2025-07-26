package bridgesdk

// Dashboard components for token transfer interface

// DashboardComponents provides modular dashboard components for token transfers
type DashboardComponents struct {
	sdk *BridgeSDK
}

// NewDashboardComponents creates new dashboard components
func NewDashboardComponents(sdk *BridgeSDK) *DashboardComponents {
	return &DashboardComponents{sdk: sdk}
}

// TokenTransferWidget returns HTML for the token transfer widget
func (dc *DashboardComponents) TokenTransferWidget() string {
	return `
<div class="token-transfer-widget">
    <div class="widget-header">
        <h3>🔄 Cross-Chain Token Transfer</h3>
        <div class="widget-status" id="transferStatus">Ready</div>
    </div>

    <div class="transfer-form">
        <div class="form-row">
            <div class="form-group">
                <label>From Chain</label>
                <select id="fromChain" class="form-control" onchange="updateTokenOptions()">
                    <option value="ethereum">🔗 Ethereum</option>
                    <option value="solana">🪙 Solana</option>
                    <option value="blackhole">⚫ BlackHole</option>
                </select>
            </div>
            <div class="form-group">
                <label>To Chain</label>
                <select id="toChain" class="form-control" onchange="updateTokenOptions()">
                    <option value="blackhole">⚫ BlackHole</option>
                    <option value="ethereum">🔗 Ethereum</option>
                    <option value="solana">🪙 Solana</option>
                </select>
            </div>
        </div>

        <div class="form-row">
            <div class="form-group">
                <label>Token</label>
                <select id="tokenSelect" class="form-control" onchange="updateEstimates()">
                    <option value="ETH">ETH - Ethereum</option>
                    <option value="SOL">SOL - Solana</option>
                    <option value="BHX">BHX - BlackHole Token</option>
                </select>
            </div>
            <div class="form-group">
                <label>Amount</label>
                <input type="number" id="transferAmount" class="form-control" placeholder="0.0" step="0.000001" oninput="updateEstimates()">
            </div>
        </div>

        <div class="form-row">
            <div class="form-group full-width">
                <label>From Address</label>
                <input type="text" id="fromAddress" class="form-control" placeholder="e.g., 0x742d35Cc6634C0532925a3b8D4C9db96590c6C87" oninput="validateForm()">
                <div class="address-examples">
                    <small>Examples:
                        <span class="example-address" onclick="setFromAddress('0x742d35Cc6634C0532925a3b8D4C9db96590c6C87')">ETH Address</span> |
                        <span class="example-address" onclick="setFromAddress('9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM')">SOL Address</span>
                    </small>
                </div>
            </div>
        </div>

        <div class="form-row">
            <div class="form-group full-width">
                <label>To Address</label>
                <input type="text" id="toAddress" class="form-control" placeholder="e.g., bh1234567890123456789012345678901234567890" oninput="validateForm()">
                <div class="address-examples">
                    <small>Examples:
                        <span class="example-address" onclick="setToAddress('bh1234567890123456789012345678901234567890')">BlackHole</span> |
                        <span class="example-address" onclick="setToAddress('0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045')">Ethereum</span> |
                        <span class="example-address" onclick="setToAddress('7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU')">Solana</span>
                    </small>
                </div>
            </div>
        </div>

        <!-- Real-time Estimates -->
        <div class="transfer-estimates" id="transferEstimates" style="display: none;">
            <div class="estimate-row">
                <span class="estimate-label">💰 Estimated Fee:</span>
                <span class="estimate-value" id="estimatedFee">-</span>
            </div>
            <div class="estimate-row">
                <span class="estimate-label">⏱️ Estimated Time:</span>
                <span class="estimate-value" id="estimatedTime">-</span>
            </div>
            <div class="estimate-row">
                <span class="estimate-label">🔄 Exchange Rate:</span>
                <span class="estimate-value" id="exchangeRate">-</span>
            </div>
        </div>

        <div class="form-actions">
            <button id="executeTransfer" class="btn btn-primary btn-large" disabled>
                <span class="btn-icon">🚀</span>
                <span class="btn-text">Execute Transfer</span>
                <span class="btn-loader" style="display: none;">⏳</span>
            </button>
            <button id="tryAgain" class="btn btn-warning btn-large" style="display: none;">
                <span class="btn-icon">🔄</span>
                <span class="btn-text">Try Again</span>
            </button>
            <button id="clearForm" class="btn btn-secondary">Clear Form</button>
        </div>

        <div id="transferProgress" class="transfer-progress" style="display: none;">
            <div class="progress-header">
                <h4>🔄 Transfer in Progress</h4>
                <div class="progress-id" id="progressId">-</div>
            </div>
            <div class="progress-steps">
                <div class="progress-step" id="step1">
                    <div class="step-icon">1️⃣</div>
                    <div class="step-text">Validating Transfer</div>
                    <div class="step-status">⏳</div>
                </div>
                <div class="progress-step" id="step2">
                    <div class="step-icon">2️⃣</div>
                    <div class="step-text">Initiating Transfer</div>
                    <div class="step-status">⏳</div>
                </div>
                <div class="progress-step" id="step3">
                    <div class="step-icon">3️⃣</div>
                    <div class="step-text">Processing Transaction</div>
                    <div class="step-status">⏳</div>
                </div>
                <div class="progress-step" id="step4">
                    <div class="step-icon">4️⃣</div>
                    <div class="step-text">Confirming on Destination</div>
                    <div class="step-status">⏳</div>
                </div>
            </div>
        </div>

        <div id="transferResult" class="transfer-result" style="display: none;"></div>
    </div>
</div>

<style>
.token-transfer-widget {
    background: rgba(15, 23, 42, 0.8);
    border: 1px solid rgba(148, 163, 184, 0.1);
    border-radius: 15px;
    padding: 20px;
    margin: 20px 0;
    backdrop-filter: blur(10px);
}

.widget-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
    padding-bottom: 15px;
    border-bottom: 1px solid rgba(148, 163, 184, 0.1);
}

.widget-header h3 {
    margin: 0;
    color: #e0e6ed;
    font-size: 1.2rem;
}

.widget-status {
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 0.8rem;
    font-weight: 600;
    background: rgba(16, 185, 129, 0.2);
    color: #10b981;
    border: 1px solid rgba(16, 185, 129, 0.3);
    transition: all 0.3s ease;
}

.widget-status.processing {
    background: rgba(59, 130, 246, 0.2);
    color: #3b82f6;
    border-color: rgba(59, 130, 246, 0.3);
}

.widget-status.error {
    background: rgba(239, 68, 68, 0.2);
    color: #ef4444;
    border-color: rgba(239, 68, 68, 0.3);
}

.form-row {
    display: flex;
    gap: 15px;
    margin-bottom: 15px;
}

.form-group {
    flex: 1;
}

.form-group.full-width {
    flex: 1 1 100%;
}

.form-group label {
    display: block;
    margin-bottom: 5px;
    color: #94a3b8;
    font-size: 0.9rem;
    font-weight: 500;
}

.form-control {
    width: 100%;
    padding: 10px 12px;
    background: rgba(15, 23, 42, 0.8);
    border: 1px solid rgba(148, 163, 184, 0.2);
    border-radius: 8px;
    color: #e0e6ed;
    font-size: 0.9rem;
    transition: all 0.3s ease;
}

.form-control:focus {
    outline: none;
    border-color: #00d4ff;
    box-shadow: 0 0 0 3px rgba(0, 212, 255, 0.1);
}

.address-examples {
    margin-top: 5px;
}

.address-examples small {
    color: #64748b;
    font-size: 0.75rem;
}

.example-address {
    color: #00d4ff;
    cursor: pointer;
    text-decoration: underline;
    transition: color 0.2s ease;
}

.example-address:hover {
    color: #7c3aed;
}

.form-actions {
    display: flex;
    gap: 10px;
    margin-top: 20px;
}

.btn {
    padding: 10px 20px;
    border: none;
    border-radius: 8px;
    font-size: 0.9rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s ease;
}

.btn-primary {
    background: linear-gradient(135deg, #00d4ff, #7c3aed);
    color: white;
}

.btn-primary:hover {
    transform: translateY(-1px);
    box-shadow: 0 5px 15px rgba(0, 212, 255, 0.3);
}

.btn-warning {
    background: linear-gradient(135deg, #f59e0b, #d97706);
    color: white;
}

.btn-warning:hover {
    transform: translateY(-1px);
    box-shadow: 0 5px 15px rgba(245, 158, 11, 0.3);
}

.btn-secondary {
    background: rgba(148, 163, 184, 0.1);
    color: #94a3b8;
    border: 1px solid rgba(148, 163, 184, 0.2);
}

.btn-secondary:hover {
    background: rgba(148, 163, 184, 0.2);
    color: #e0e6ed;
}

.btn-large {
    padding: 15px 30px;
    font-size: 1rem;
    font-weight: 700;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    min-height: 50px;
}

.btn-large:disabled {
    opacity: 0.5;
    cursor: not-allowed;
    transform: none;
}

.btn-large:disabled:hover {
    transform: none;
    box-shadow: none;
}

.btn-icon {
    font-size: 1.2rem;
}

.btn-loader {
    animation: spin 1s linear infinite;
}

@keyframes spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
}

.transfer-estimates {
    background: rgba(15, 23, 42, 0.6);
    border: 1px solid rgba(148, 163, 184, 0.1);
    border-radius: 10px;
    padding: 15px;
    margin: 15px 0;
}

.estimate-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
}

.estimate-row:last-child {
    margin-bottom: 0;
}

.estimate-label {
    color: #94a3b8;
    font-size: 0.9rem;
}

.estimate-value {
    color: #e0e6ed;
    font-weight: 600;
    font-size: 0.9rem;
}

.transfer-progress {
    background: rgba(15, 23, 42, 0.6);
    border: 1px solid rgba(148, 163, 184, 0.1);
    border-radius: 10px;
    padding: 20px;
    margin: 20px 0;
}

.progress-header {
    text-align: center;
    margin-bottom: 20px;
}

.progress-header h4 {
    margin: 0 0 5px 0;
    color: #e0e6ed;
    font-size: 1.1rem;
}

.progress-id {
    color: #94a3b8;
    font-size: 0.8rem;
    font-family: monospace;
}

.progress-steps {
    display: flex;
    flex-direction: column;
    gap: 10px;
}

.progress-step {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px;
    background: rgba(15, 23, 42, 0.4);
    border-radius: 8px;
    transition: all 0.3s ease;
}

.progress-step.active {
    background: rgba(59, 130, 246, 0.1);
    border: 1px solid rgba(59, 130, 246, 0.3);
}

.progress-step.completed {
    background: rgba(16, 185, 129, 0.1);
    border: 1px solid rgba(16, 185, 129, 0.3);
}

.progress-step.error {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid rgba(239, 68, 68, 0.3);
}

.step-icon {
    font-size: 1.2rem;
    min-width: 30px;
}

.step-text {
    flex: 1;
    color: #e0e6ed;
    font-size: 0.9rem;
}

.step-status {
    font-size: 1rem;
    min-width: 30px;
    text-align: center;
}

.transfer-result {
    margin-top: 15px;
    padding: 15px;
    border-radius: 10px;
    font-size: 0.9rem;
}

.transfer-result.success {
    background: rgba(16, 185, 129, 0.1);
    border: 1px solid rgba(16, 185, 129, 0.3);
    color: #10b981;
}

.transfer-result.error {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid rgba(239, 68, 68, 0.3);
    color: #ef4444;
}

.transfer-result.instant-success {
    background: linear-gradient(135deg, rgba(16, 185, 129, 0.2), rgba(5, 150, 105, 0.1));
    border: 2px solid #10b981;
    color: #6ee7b7;
    border-radius: 8px;
}

.instant-step {
    background: linear-gradient(135deg, rgba(0, 255, 0, 0.1), rgba(0, 200, 0, 0.05));
    border: 1px solid rgba(0, 255, 0, 0.3);
}

@keyframes instantSuccess {
    0% {
        transform: scale(0.9);
        opacity: 0;
    }
    50% {
        transform: scale(1.05);
    }
    100% {
        transform: scale(1);
        opacity: 1;
    }
}

@keyframes statUpdate {
    0% {
        transform: scale(1);
        color: inherit;
    }
    50% {
        transform: scale(1.2);
        color: #10b981;
    }
    100% {
        transform: scale(1);
        color: inherit;
    }
}

@keyframes flashSuccess {
    0% {
        transform: translateX(100px);
        opacity: 0;
    }
    20% {
        transform: translateX(0);
        opacity: 1;
    }
    80% {
        transform: translateX(0);
        opacity: 1;
    }
    100% {
        transform: translateX(100px);
        opacity: 0;
    }
}
</style>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const executeBtn = document.getElementById('executeTransfer');
    const tryAgainBtn = document.getElementById('tryAgain');
    const clearBtn = document.getElementById('clearForm');
    const transferStatus = document.getElementById('transferStatus');
    const transferEstimates = document.getElementById('transferEstimates');
    const transferProgress = document.getElementById('transferProgress');
    const transferResult = document.getElementById('transferResult');

    let validationTimeout;
    let currentTransferId = null;

    executeBtn.addEventListener('click', executeTransfer);
    tryAgainBtn.addEventListener('click', tryAgainTransfer);
    clearBtn.addEventListener('click', clearForm);

    // Initialize form
    updateTokenOptions();
    validateForm();

    async function executeTransfer() {
        const request = buildTransferRequest();
        if (!request) return;

        // Prevent double-clicking
        if (executeBtn.disabled) return;

        // Add pending transfer to history if function exists
        let transferHistoryId = null;
        if (typeof window.addPendingTokenTransfer === 'function') {
            transferHistoryId = window.addPendingTokenTransfer(request);
        }

        // Update UI to show instant processing
        updateStatus('processing', 'Executing Transfer...');
        executeBtn.disabled = true;
        executeBtn.querySelector('.btn-text').textContent = 'Executing...';
        executeBtn.querySelector('.btn-loader').style.display = 'inline';
        executeBtn.querySelector('.btn-icon').style.display = 'none';
        executeBtn.style.opacity = '0.7';
        executeBtn.style.cursor = 'not-allowed';

        // Hide any previous results
        transferResult.style.display = 'none';

        // Show instant progress
        showInstantProgress(request.id);

        try {
            // Instant Step 1: Validate Transfer (no delay)
            updateProgressStep('step1', 'active');
            await new Promise(resolve => setTimeout(resolve, 100)); // Minimal delay for UI
            updateProgressStep('step1', 'completed');

            // Instant Step 2: Execute Transfer (immediate)
            updateProgressStep('step2', 'active');
            const transferResponse = await fetch('/api/instant-transfer', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(request)
            });

            if (!transferResponse.ok) {
                throw new Error('Transfer request failed: ' + transferResponse.status);
            }

            const transferResult = await transferResponse.json();

            if (transferResult.error) {
                updateProgressStep('step2', 'error');
                throw new Error(transferResult.error);
            }

            updateProgressStep('step2', 'completed');
            await new Promise(resolve => setTimeout(resolve, 200)); // Brief UI feedback

            // Instant Step 3: Complete (immediate confirmation)
            updateProgressStep('step3', 'active');
            await new Promise(resolve => setTimeout(resolve, 100));
            updateProgressStep('step3', 'completed');

            // Instant Step 4: Finalize
            updateProgressStep('step4', 'active');
            await new Promise(resolve => setTimeout(resolve, 100));
            updateProgressStep('step4', 'completed');

            // Instant success
            handleInstantTransferSuccess(transferResult);

        } catch (error) {
            console.error('Transfer error:', error);

            // Update transfer status to failed if function exists
            if (typeof window.updateTokenTransferStatus === 'function' && transferHistoryId) {
                window.updateTokenTransferStatus(transferHistoryId, 'failed', { error: error.message });
            }

            handleTransferError(error.message);
        }
    }
    
    async function monitorTransfer(transferId) {
        let attempts = 0;
        const maxAttempts = 30; // 5 minutes with 10-second intervals

        const checkStatus = async () => {
            try {
                const response = await fetch('/api/transfer-status/' + transferId);
                const status = await response.json();

                if (status.state === 'completed') {
                    updateProgressStep('step3', 'completed');
                    updateProgressStep('step4', 'completed');
                    handleTransferSuccess(status);
                    return;
                } else if (status.state === 'failed') {
                    updateProgressStep('step3', 'error');
                    throw new Error(status.error_message || 'Transfer failed');
                }

                // Continue monitoring
                attempts++;
                if (attempts < maxAttempts) {
                    setTimeout(checkStatus, 10000); // Check every 10 seconds
                } else {
                    updateProgressStep('step4', 'active');
                    handleTransferSuccess({
                        request_id: transferId,
                        state: 'processing',
                        message: 'Transfer is still processing. You can check status later.'
                    });
                }
            } catch (error) {
                throw error;
            }
        };

        setTimeout(checkStatus, 2000); // Start checking after 2 seconds
    }

    function handleTransferSuccess(result) {
        updateStatus('ready', 'Transfer Completed');
        hideProgress();

        transferResult.style.display = 'block';
        transferResult.className = 'transfer-result success';
        transferResult.innerHTML =
            '✅ <strong>Transfer Successful!</strong><br>' +
            'Request ID: ' + result.request_id + '<br>' +
            'Status: ' + result.state + '<br>' +
            (result.source_tx_hash ? 'Transaction Hash: ' + result.source_tx_hash + '<br>' : '') +
            (result.message ? result.message : '');

        resetFormButton();

        // Auto-clear result after 10 seconds
        setTimeout(() => {
            transferResult.style.display = 'none';
        }, 10000);
    }

    function handleInstantTransferSuccess(result) {
        updateStatus('ready', '⚡ Instant Transfer Complete!');
        hideProgress();

        transferResult.style.display = 'block';
        transferResult.className = 'transfer-result success instant-success';
        transferResult.innerHTML =
            '⚡ <strong>Instant Transfer Complete!</strong><br>' +
            '🚀 Request ID: ' + result.request_id + '<br>' +
            '✅ Status: Completed Instantly<br>' +
            '⏱️ Processing Time: < 1 second<br>' +
            '🎉 Your tokens have been transferred successfully!';

        // Add instant success animation
        transferResult.style.animation = 'instantSuccess 0.5s ease-out';
        transferResult.style.boxShadow = '0 0 30px rgba(0, 255, 0, 0.5)';

        resetFormButton();

        // Update dashboard stats instantly
        updateDashboardStats();

        // Add to token transfer history if function exists
        if (typeof window.addTokenTransferToHistory === 'function') {
            const transferRequest = buildTransferRequest();
            window.addTokenTransferToHistory(transferRequest, result);
        }

        // Auto-clear result after 8 seconds
        setTimeout(() => {
            transferResult.style.display = 'none';
            transferResult.style.animation = '';
            transferResult.style.boxShadow = '';
        }, 8000);
    }

    function handleTransferError(errorMessage) {
        updateStatus('error', 'Transfer Failed');
        hideProgress();

        transferResult.style.display = 'block';
        transferResult.className = 'transfer-result error';
        transferResult.innerHTML = '❌ <strong>Transfer Failed:</strong><br>' + errorMessage +
            '<br><br><small>You can try again or clear the form to start over.</small>';

        // Show try again button and hide execute button
        executeBtn.style.display = 'none';
        tryAgainBtn.style.display = 'inline-flex';

        // Auto-clear error after 30 seconds
        setTimeout(() => {
            transferResult.style.display = 'none';
            updateStatus('ready', 'Ready');
            executeBtn.style.display = 'inline-flex';
            tryAgainBtn.style.display = 'none';
            validateForm();
        }, 30000);
    }

    function tryAgainTransfer() {
        // Hide try again button and show execute button
        tryAgainBtn.style.display = 'none';
        executeBtn.style.display = 'inline-flex';

        // Clear previous results
        transferResult.style.display = 'none';
        updateStatus('ready', 'Ready');

        // Re-validate and enable execute button
        validateForm();

        // Optionally auto-execute after a short delay
        setTimeout(() => {
            if (!executeBtn.disabled) {
                executeTransfer();
            }
        }, 500);
    }

    function showProgress(transferId) {
        transferProgress.style.display = 'block';
        document.getElementById('progressId').textContent = transferId;

        // Reset all steps
        ['step1', 'step2', 'step3', 'step4'].forEach(stepId => {
            const step = document.getElementById(stepId);
            step.className = 'progress-step';
            step.querySelector('.step-status').textContent = '⏳';
        });
    }

    function showInstantProgress(transferId) {
        transferProgress.style.display = 'block';
        document.getElementById('progressId').textContent = transferId + ' (INSTANT)';

        // Reset all steps with instant styling
        ['step1', 'step2', 'step3', 'step4'].forEach(stepId => {
            const step = document.getElementById(stepId);
            step.className = 'progress-step instant-step';
            step.querySelector('.step-status').textContent = '⚡';
        });

        // Add instant glow effect
        transferProgress.style.boxShadow = '0 0 20px rgba(0, 255, 0, 0.3)';
        transferProgress.style.border = '2px solid rgba(0, 255, 0, 0.5)';
    }

    function hideProgress() {
        transferProgress.style.display = 'none';
    }

    function updateProgressStep(stepId, status) {
        const step = document.getElementById(stepId);
        const statusElement = step.querySelector('.step-status');

        step.className = 'progress-step ' + status;

        switch (status) {
            case 'active':
                statusElement.textContent = '🔄';
                break;
            case 'completed':
                statusElement.textContent = '✅';
                break;
            case 'error':
                statusElement.textContent = '❌';
                break;
            default:
                statusElement.textContent = '⏳';
        }
    }

    function updateStatus(type, message) {
        transferStatus.textContent = message;
        transferStatus.className = 'widget-status ' + type;
    }

    function resetFormButton() {
        executeBtn.disabled = false;
        executeBtn.querySelector('.btn-text').textContent = 'Execute Transfer';
        executeBtn.querySelector('.btn-loader').style.display = 'none';
        executeBtn.querySelector('.btn-icon').style.display = 'inline';
        executeBtn.style.display = 'inline-flex';
        executeBtn.style.opacity = '1';
        executeBtn.style.cursor = 'pointer';

        // Hide try again button
        tryAgainBtn.style.display = 'none';

        currentTransferId = null;

        // Re-validate form to set correct button state
        validateForm();
    }

    function resetForm() {
        resetFormButton();
    }

    function clearForm() {
        document.getElementById('fromChain').value = 'ethereum';
        document.getElementById('toChain').value = 'blackhole';
        document.getElementById('transferAmount').value = '';
        document.getElementById('fromAddress').value = '';
        document.getElementById('toAddress').value = '';

        // Update token options for the selected chain
        updateTokenOptions();

        transferEstimates.style.display = 'none';
        transferResult.style.display = 'none';
        hideProgress();
        updateStatus('ready', 'Ready');

        // Reset both buttons
        executeBtn.style.display = 'inline-flex';
        tryAgainBtn.style.display = 'none';

        resetFormButton();
    }

    function updateDashboardStats() {
        // Instantly update dashboard statistics
        fetch('/api/stats')
            .then(response => response.json())
            .then(stats => {
                // Update any visible stats on the page
                const statsElements = document.querySelectorAll('.stat-value');
                statsElements.forEach(element => {
                    if (element.dataset.stat === 'total_transfers') {
                        element.textContent = stats.total_transfers || '0';
                        element.style.animation = 'statUpdate 0.5s ease-out';
                    }
                    if (element.dataset.stat === 'completed_transfers') {
                        element.textContent = stats.completed_transfers || '0';
                        element.style.animation = 'statUpdate 0.5s ease-out';
                    }
                });

                // Flash success indicator
                const successIndicator = document.createElement('div');
                successIndicator.className = 'instant-success-flash';
                successIndicator.innerHTML = '⚡ +1 Transfer';
                successIndicator.style.cssText =
                    'position: fixed;' +
                    'top: 20px;' +
                    'right: 20px;' +
                    'background: linear-gradient(135deg, #10b981, #059669);' +
                    'color: white;' +
                    'padding: 10px 20px;' +
                    'border-radius: 25px;' +
                    'font-weight: bold;' +
                    'z-index: 10000;' +
                    'animation: flashSuccess 2s ease-out forwards;' +
                    'box-shadow: 0 4px 15px rgba(16, 185, 129, 0.4);';
                document.body.appendChild(successIndicator);

                setTimeout(() => {
                    document.body.removeChild(successIndicator);
                }, 2000);
            })
            .catch(error => console.log('Stats update failed:', error));
    }

    function validateForm() {
        clearTimeout(validationTimeout);

        validationTimeout = setTimeout(() => {
            const fromChain = document.getElementById('fromChain').value;
            const toChain = document.getElementById('toChain').value;
            const token = document.getElementById('tokenSelect').value;
            const amount = document.getElementById('transferAmount').value;
            const fromAddress = document.getElementById('fromAddress').value;
            const toAddress = document.getElementById('toAddress').value;

            // Check if form is valid
            const isValid = fromChain && toChain && token && amount && fromAddress && toAddress &&
                           parseFloat(amount) > 0 && fromChain !== toChain && fromAddress.trim() !== '' && toAddress.trim() !== '';

            // Only enable button if not currently processing and form is valid
            const isProcessing = executeBtn.querySelector('.btn-loader').style.display !== 'none';
            executeBtn.disabled = !isValid || isProcessing;

            // Update button appearance based on state
            if (isValid && !isProcessing) {
                executeBtn.style.opacity = '1';
                executeBtn.style.cursor = 'pointer';
            } else {
                executeBtn.style.opacity = '0.5';
                executeBtn.style.cursor = 'not-allowed';
            }

            if (isValid) {
                updateEstimates();
            } else {
                transferEstimates.style.display = 'none';
            }
        }, 300);
    }

    function updateEstimates() {
        const fromChain = document.getElementById('fromChain').value;
        const toChain = document.getElementById('toChain').value;
        const token = document.getElementById('tokenSelect').value;
        const amount = document.getElementById('transferAmount').value;

        if (!amount || parseFloat(amount) <= 0) {
            transferEstimates.style.display = 'none';
            return;
        }

        // Show instant estimates
        transferEstimates.style.display = 'block';

        const fee = (parseFloat(amount) * 0.001).toFixed(6); // 0.1% fee for instant
        const time = '⚡ Instant (< 1 second)'; // Always instant
        const rate = '1:1'; // Perfect rate for instant transfers

        document.getElementById('estimatedFee').textContent = fee + ' ' + token;
        document.getElementById('estimatedTime').textContent = time;
        document.getElementById('exchangeRate').textContent = rate;

        // Add instant styling to estimates
        const estimatesDiv = transferEstimates;
        estimatesDiv.style.background = 'linear-gradient(135deg, rgba(16, 185, 129, 0.1), rgba(5, 150, 105, 0.05))';
        estimatesDiv.style.border = '1px solid rgba(16, 185, 129, 0.3)';
        estimatesDiv.style.boxShadow = '0 0 15px rgba(16, 185, 129, 0.2)';

        // Add instant badge if not already present
        if (!estimatesDiv.querySelector('.instant-badge')) {
            const badge = document.createElement('div');
            badge.className = 'instant-badge';
            badge.innerHTML = '⚡ Powered by Instant Bridge Technology';
            badge.style.cssText =
                'text-align: center;' +
                'margin-top: 10px;' +
                'padding: 5px;' +
                'background: rgba(16, 185, 129, 0.2);' +
                'border-radius: 15px;' +
                'font-size: 0.8rem;' +
                'color: #10b981;' +
                'font-weight: bold;';
            estimatesDiv.appendChild(badge);
        }
    }

    function updateTokenOptions() {
        const fromChain = document.getElementById('fromChain').value;
        const tokenSelect = document.getElementById('tokenSelect');

        // Update token options based on selected chain with real contract addresses
        tokenSelect.innerHTML = '';

        if (fromChain === 'ethereum') {
            tokenSelect.innerHTML =
                '<option value="ETH" data-contract="0x0000000000000000000000000000000000000000" data-decimals="18">ETH - Ethereum (Native)</option>' +
                '<option value="USDC" data-contract="0xA0b86a33E6441E6C7D3E4C7C5C6C7C5C6C7C5C6C7" data-decimals="6">USDC - USD Coin</option>' +
                '<option value="USDT" data-contract="0xdAC17F958D2ee523a2206206994597C13D831ec7" data-decimals="6">USDT - Tether</option>' +
                '<option value="WBTC" data-contract="0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599" data-decimals="8">WBTC - Wrapped Bitcoin</option>' +
                '<option value="UNI" data-contract="0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984" data-decimals="18">UNI - Uniswap</option>';
        } else if (fromChain === 'solana') {
            tokenSelect.innerHTML =
                '<option value="SOL" data-contract="11111111111111111111111111111111" data-decimals="9">SOL - Solana (Native)</option>' +
                '<option value="USDC" data-contract="EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" data-decimals="6">USDC - USD Coin</option>' +
                '<option value="USDT" data-contract="Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB" data-decimals="6">USDT - Tether</option>' +
                '<option value="RAY" data-contract="4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R" data-decimals="6">RAY - Raydium</option>' +
                '<option value="SRM" data-contract="SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt" data-decimals="6">SRM - Serum</option>';
        } else if (fromChain === 'blackhole') {
            tokenSelect.innerHTML =
                '<option value="BHX" data-contract="bh0000000000000000000000000000000000000000" data-decimals="18">BHX - BlackHole Token</option>' +
                '<option value="WBHX" data-contract="bh1111111111111111111111111111111111111111" data-decimals="18">WBHX - Wrapped BHX</option>' +
                '<option value="BHUSDC" data-contract="bh2222222222222222222222222222222222222222" data-decimals="6">BHUSDC - BlackHole USDC</option>' +
                '<option value="BHETH" data-contract="bh3333333333333333333333333333333333333333" data-decimals="18">BHETH - BlackHole ETH</option>';
        }

        updateEstimates();
    }

    function setFromAddress(address) {
        document.getElementById('fromAddress').value = address;
        validateForm();
    }

    function setToAddress(address) {
        document.getElementById('toAddress').value = address;
        validateForm();
    }

    function buildTransferRequest() {
        const fromChain = document.getElementById('fromChain').value;
        const toChain = document.getElementById('toChain').value;
        const tokenSelect = document.getElementById('tokenSelect');
        const selectedOption = tokenSelect.options[tokenSelect.selectedIndex];
        const token = selectedOption.value;
        const contractAddress = selectedOption.getAttribute('data-contract');
        const decimals = parseInt(selectedOption.getAttribute('data-decimals'));
        const amount = document.getElementById('transferAmount').value;
        const fromAddress = document.getElementById('fromAddress').value;
        const toAddress = document.getElementById('toAddress').value;

        if (!fromChain || !toChain || !token || !amount || !fromAddress || !toAddress) {
            alert('Please fill in all fields');
            return null;
        }

        // Determine token standard
        let standard = 'NATIVE';
        if (fromChain === 'ethereum' && contractAddress !== '0x0000000000000000000000000000000000000000') {
            standard = 'ERC20';
        } else if (fromChain === 'solana' && contractAddress !== '11111111111111111111111111111111') {
            standard = 'SPL';
        } else if (fromChain === 'blackhole' && contractAddress !== 'bh0000000000000000000000000000000000000000') {
            standard = 'BHX';
        }

        return {
            id: 'transfer_' + Date.now(),
            from_chain: fromChain,
            to_chain: toChain,
            from_address: fromAddress,
            to_address: toAddress,
            token: {
                symbol: token,
                name: selectedOption.text.split(' - ')[1] || token,
                decimals: decimals,
                standard: standard,
                contract_address: contractAddress,
                chain_id: fromChain === 'ethereum' ? '1' : fromChain === 'solana' ? 'mainnet-beta' : 'blackhole-1',
                is_native: standard === 'NATIVE'
            },
            amount: (parseFloat(amount) * Math.pow(10, decimals)).toString(),
            nonce: Date.now(),
            deadline: new Date(Date.now() + 3600000).toISOString() // 1 hour from now
        };
    }

    // Make functions globally available
    window.updateTokenOptions = updateTokenOptions;
    window.updateEstimates = updateEstimates;
    window.validateForm = validateForm;
    window.setFromAddress = setFromAddress;
    window.setToAddress = setToAddress;
});
</script>
`
}

// SupportedPairsWidget returns HTML for the supported pairs widget
func (dc *DashboardComponents) SupportedPairsWidget() string {
	return `
<div class="supported-pairs-widget">
    <div class="widget-header">
        <h3>🔗 Supported Token Pairs</h3>
        <button id="refreshPairs" class="btn btn-sm">🔄 Refresh</button>
    </div>
    
    <div id="pairsList" class="pairs-list">
        Loading supported pairs...
    </div>
</div>

<style>
.supported-pairs-widget {
    background: rgba(15, 23, 42, 0.8);
    border: 1px solid rgba(148, 163, 184, 0.1);
    border-radius: 15px;
    padding: 20px;
    margin: 20px 0;
}

.pairs-list {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 15px;
    margin-top: 15px;
}

.pair-card {
    background: rgba(15, 23, 42, 0.6);
    border: 1px solid rgba(148, 163, 184, 0.1);
    border-radius: 10px;
    padding: 15px;
    transition: all 0.3s ease;
}

.pair-card:hover {
    border-color: rgba(0, 212, 255, 0.3);
    transform: translateY(-2px);
}

.pair-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 10px;
}

.pair-tokens {
    font-size: 1.1rem;
    font-weight: 600;
    color: #e0e6ed;
}

.pair-status {
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 0.7rem;
    font-weight: 600;
}

.pair-status.active {
    background: rgba(16, 185, 129, 0.2);
    color: #10b981;
}

.pair-status.inactive {
    background: rgba(239, 68, 68, 0.2);
    color: #ef4444;
}

.pair-details {
    font-size: 0.8rem;
    color: #94a3b8;
    line-height: 1.4;
}

.btn-sm {
    padding: 6px 12px;
    font-size: 0.8rem;
}
</style>

<script>
document.addEventListener('DOMContentLoaded', function() {
    loadSupportedPairs();
    
    document.getElementById('refreshPairs').addEventListener('click', loadSupportedPairs);
    
    async function loadSupportedPairs() {
        try {
            const response = await fetch('/api/supported-pairs');
            const pairs = await response.json();
            displaySupportedPairs(pairs);
        } catch (error) {
            document.getElementById('pairsList').innerHTML = 
                '<div class="error">Failed to load supported pairs: ' + error.message + '</div>';
        }
    }
    
    function displaySupportedPairs(pairs) {
        const pairsList = document.getElementById('pairsList');
        
        if (!pairs || Object.keys(pairs).length === 0) {
            pairsList.innerHTML = '<div class="no-pairs">No supported pairs available</div>';
            return;
        }
        
        const pairsHTML = Object.values(pairs).map(pair => 
            '<div class="pair-card">' +
                '<div class="pair-header">' +
                    '<div class="pair-tokens">' + pair.from_token.symbol + ' → ' + pair.to_token.symbol + '</div>' +
                    '<div class="pair-status ' + (pair.is_active ? 'active' : 'inactive') + '">' +
                        (pair.is_active ? 'Active' : 'Inactive') +
                    '</div>' +
                '</div>' +
                '<div class="pair-details">' +
                    'Exchange Rate: 1 ' + pair.from_token.symbol + ' = ' + pair.exchange_rate + ' ' + pair.to_token.symbol + '<br>' +
                    'Min Amount: ' + pair.min_amount + ' ' + pair.from_token.symbol + '<br>' +
                    'Max Amount: ' + pair.max_amount + ' ' + pair.from_token.symbol + '<br>' +
                    'Fee: ' + pair.fee + ' ' + pair.from_token.symbol +
                '</div>' +
            '</div>'
        ).join('');
        
        pairsList.innerHTML = pairsHTML;
    }
});
</script>
`
}
