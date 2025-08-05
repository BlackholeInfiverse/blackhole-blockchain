// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title BHXToken
 * @dev BlackHole (BHX) Token - ERC20 implementation for DEX trading
 * 
 * Features:
 * - Standard ERC20 functionality
 * - Burnable tokens
 * - Pausable transfers (emergency stop)
 * - Owner controls for bridge integration
 * - Bridge minting/burning for cross-chain transfers
 * - Anti-whale protection
 * - Transaction limits
 */
contract BHXToken is ERC20, ERC20Burnable, Pausable, Ownable, ReentrancyGuard {
    
    // Token configuration
    uint256 public constant MAX_SUPPLY = 1_000_000_000 * 10**18; // 1 billion BHX
    uint256 public constant INITIAL_SUPPLY = 100_000_000 * 10**18; // 100 million BHX initial
    
    // Bridge integration
    mapping(address => bool) public bridgeOperators;
    mapping(address => bool) public blacklistedAddresses;
    
    // Anti-whale protection
    uint256 public maxTransactionAmount = 1_000_000 * 10**18; // 1M BHX max per transaction
    uint256 public maxWalletAmount = 10_000_000 * 10**18; // 10M BHX max per wallet
    bool public limitsEnabled = true;
    
    // Events
    event BridgeOperatorAdded(address indexed operator);
    event BridgeOperatorRemoved(address indexed operator);
    event AddressBlacklisted(address indexed account);
    event AddressUnblacklisted(address indexed account);
    event LimitsUpdated(uint256 maxTx, uint256 maxWallet);
    event BridgeMint(address indexed to, uint256 amount, string indexed fromChain);
    event BridgeBurn(address indexed from, uint256 amount, string indexed toChain);
    
    modifier onlyBridgeOperator() {
        require(bridgeOperators[msg.sender], "BHX: Not a bridge operator");
        _;
    }
    
    modifier notBlacklisted(address account) {
        require(!blacklistedAddresses[account], "BHX: Address is blacklisted");
        _;
    }
    
    constructor() ERC20("BlackHole Token", "BHX") {
        // Mint initial supply to deployer
        _mint(msg.sender, INITIAL_SUPPLY);
        
        // Add deployer as initial bridge operator
        bridgeOperators[msg.sender] = true;
        emit BridgeOperatorAdded(msg.sender);
    }
    
    /**
     * @dev Bridge Functions - For cross-chain integration
     */
    function bridgeMint(address to, uint256 amount, string calldata fromChain) 
        external 
        onlyBridgeOperator 
        nonReentrant 
        notBlacklisted(to) 
    {
        require(to != address(0), "BHX: Cannot mint to zero address");
        require(amount > 0, "BHX: Amount must be greater than 0");
        require(totalSupply() + amount <= MAX_SUPPLY, "BHX: Would exceed max supply");
        
        _mint(to, amount);
        emit BridgeMint(to, amount, fromChain);
    }
    
    function bridgeBurn(address from, uint256 amount, string calldata toChain) 
        external 
        onlyBridgeOperator 
        nonReentrant 
        notBlacklisted(from) 
    {
        require(from != address(0), "BHX: Cannot burn from zero address");
        require(amount > 0, "BHX: Amount must be greater than 0");
        require(balanceOf(from) >= amount, "BHX: Insufficient balance to burn");
        
        _burn(from, amount);
        emit BridgeBurn(from, amount, toChain);
    }
    
    /**
     * @dev Admin Functions
     */
    function addBridgeOperator(address operator) external onlyOwner {
        require(operator != address(0), "BHX: Invalid operator address");
        bridgeOperators[operator] = true;
        emit BridgeOperatorAdded(operator);
    }
    
    function removeBridgeOperator(address operator) external onlyOwner {
        bridgeOperators[operator] = false;
        emit BridgeOperatorRemoved(operator);
    }
    
    function blacklistAddress(address account) external onlyOwner {
        require(account != address(0), "BHX: Invalid address");
        blacklistedAddresses[account] = true;
        emit AddressBlacklisted(account);
    }
    
    function unblacklistAddress(address account) external onlyOwner {
        blacklistedAddresses[account] = false;
        emit AddressUnblacklisted(account);
    }
    
    function updateLimits(uint256 _maxTransactionAmount, uint256 _maxWalletAmount) external onlyOwner {
        require(_maxTransactionAmount >= 100_000 * 10**18, "BHX: Max transaction too low"); // Min 100K
        require(_maxWalletAmount >= 1_000_000 * 10**18, "BHX: Max wallet too low"); // Min 1M
        
        maxTransactionAmount = _maxTransactionAmount;
        maxWalletAmount = _maxWalletAmount;
        emit LimitsUpdated(_maxTransactionAmount, _maxWalletAmount);
    }
    
    function setLimitsEnabled(bool _enabled) external onlyOwner {
        limitsEnabled = _enabled;
    }
    
    function pause() external onlyOwner {
        _pause();
    }
    
    function unpause() external onlyOwner {
        _unpause();
    }
    
    /**
     * @dev Override transfer functions to add protections
     */
    function transfer(address to, uint256 amount) 
        public 
        override 
        whenNotPaused 
        notBlacklisted(msg.sender) 
        notBlacklisted(to) 
        returns (bool) 
    {
        if (limitsEnabled) {
            require(amount <= maxTransactionAmount, "BHX: Transfer amount exceeds limit");
            require(balanceOf(to) + amount <= maxWalletAmount, "BHX: Recipient wallet limit exceeded");
        }
        
        return super.transfer(to, amount);
    }
    
    function transferFrom(address from, address to, uint256 amount) 
        public 
        override 
        whenNotPaused 
        notBlacklisted(from) 
        notBlacklisted(to) 
        returns (bool) 
    {
        if (limitsEnabled) {
            require(amount <= maxTransactionAmount, "BHX: Transfer amount exceeds limit");
            require(balanceOf(to) + amount <= maxWalletAmount, "BHX: Recipient wallet limit exceeded");
        }
        
        return super.transferFrom(from, to, amount);
    }
    
    /**
     * @dev Emergency functions
     */
    function emergencyWithdraw() external onlyOwner {
        payable(owner()).transfer(address(this).balance);
    }
    
    function emergencyTokenWithdraw(address token, uint256 amount) external onlyOwner {
        require(token != address(this), "BHX: Cannot withdraw BHX tokens");
        IERC20(token).transfer(owner(), amount);
    }
    
    /**
     * @dev View functions
     */
    function isBridgeOperator(address account) external view returns (bool) {
        return bridgeOperators[account];
    }
    
    function isBlacklisted(address account) external view returns (bool) {
        return blacklistedAddresses[account];
    }
    
    function getTokenInfo() external view returns (
        string memory name,
        string memory symbol,
        uint8 decimals,
        uint256 totalSupply,
        uint256 maxSupply,
        bool paused,
        bool limitsEnabled
    ) {
        return (
            name(),
            symbol(),
            decimals(),
            totalSupply(),
            MAX_SUPPLY,
            paused(),
            limitsEnabled
        );
    }
}
