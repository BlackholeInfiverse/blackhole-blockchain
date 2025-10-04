// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title BlackHole (BHX) Token
 * @dev ERC20 Token for BlackHole Blockchain ecosystem
 * 
 * Features:
 * - Standard ERC20 functionality
 * - Burnable tokens
 * - Pausable transfers
 * - Bridge compatibility
 * - Exchange-ready
 */
contract BHXToken is ERC20, ERC20Burnable, Pausable, Ownable {
    
    // Maximum supply: 1 billion BHX (as per tokenomics spec)
    uint256 public constant MAX_SUPPLY = 1_000_000_000 * 10**18;
    
    // Initial circulating supply: 350 million BHX (35%)
    uint256 public constant INITIAL_CIRCULATING_SUPPLY = 350_000_000 * 10**18;
    
    // Distribution allocations (as per tokenomics)
    uint256 public constant PRIVATE_SALE_ALLOCATION = 100_000_000 * 10**18; // 10%
    uint256 public constant PUBLIC_SALE_ALLOCATION = 200_000_000 * 10**18;  // 20%
    uint256 public constant DEV_FUND_ALLOCATION = 150_000_000 * 10**18;      // 15%
    uint256 public constant STAKING_REWARDS_ALLOCATION = 100_000_000 * 10**18; // 10%
    uint256 public constant TEAM_ADVISORS_ALLOCATION = 150_000_000 * 10**18;   // 15%
    uint256 public constant ECOSYSTEM_ALLOCATION = 150_000_000 * 10**18;       // 15%
    uint256 public constant RESERVE_ALLOCATION = 150_000_000 * 10**18;         // 15%
    
    // Bridge contract address (will be set after bridge deployment)
    address public bridgeContract;
    
    // Mapping to track bridge mints/burns
    mapping(address => bool) public authorizedBridges;
    
    // Fee burn mechanism (0.1% of transaction fees as per tokenomics)
    uint256 public constant FEE_BURN_RATE = 10; // 0.1% = 10/10000
    uint256 public totalBurned;
    
    // Events
    event BridgeContractUpdated(address indexed oldBridge, address indexed newBridge);
    event BridgeAuthorized(address indexed bridge, bool authorized);
    event TokensMinted(address indexed to, uint256 amount, string indexed blackholeAddress);
    event TokensBurned(address indexed from, uint256 amount, string indexed blackholeAddress);
    event FeesBurned(uint256 amount, address indexed burner);
    
    /**
     * @dev Constructor
     * @param initialSupply Initial supply to mint to deployer (for initial liquidity)
     * @notice Defaults to INITIAL_CIRCULATING_SUPPLY if 0 is passed
     */
    constructor(uint256 initialSupply) ERC20("BlackHole", "BHX") {
        uint256 mintAmount = initialSupply == 0 ? INITIAL_CIRCULATING_SUPPLY : initialSupply;
        require(mintAmount <= MAX_SUPPLY, "Initial supply exceeds maximum");
        require(mintAmount <= INITIAL_CIRCULATING_SUPPLY, "Exceeds initial circulating supply");
        _mint(msg.sender, mintAmount);
    }
    
    /**
     * @dev Mint tokens - only for bridge operations
     * @param to Address to mint tokens to
     * @param amount Amount to mint
     * @param blackholeAddress Corresponding BlackHole chain address
     */
    function bridgeMint(address to, uint256 amount, string calldata blackholeAddress) external {
        require(authorizedBridges[msg.sender], "Not authorized bridge");
        require(totalSupply() + amount <= MAX_SUPPLY, "Would exceed max supply");
        
        _mint(to, amount);
        emit TokensMinted(to, amount, blackholeAddress);
    }
    
    /**
     * @dev Burn tokens - only for bridge operations
     * @param from Address to burn tokens from
     * @param amount Amount to burn
     * @param blackholeAddress Destination BlackHole chain address
     */
    function bridgeBurn(address from, uint256 amount, string calldata blackholeAddress) external {
        require(authorizedBridges[msg.sender], "Not authorized bridge");
        require(balanceOf(from) >= amount, "Insufficient balance");
        
        _burn(from, amount);
        emit TokensBurned(from, amount, blackholeAddress);
    }
    
    /**
     * @dev Set bridge contract address
     * @param _bridgeContract New bridge contract address
     */
    function setBridgeContract(address _bridgeContract) external onlyOwner {
        address oldBridge = bridgeContract;
        bridgeContract = _bridgeContract;
        
        // Authorize new bridge and deauthorize old one
        if (oldBridge != address(0)) {
            authorizedBridges[oldBridge] = false;
        }
        if (_bridgeContract != address(0)) {
            authorizedBridges[_bridgeContract] = true;
        }
        
        emit BridgeContractUpdated(oldBridge, _bridgeContract);
    }
    
    /**
     * @dev Authorize/deauthorize bridge contracts
     * @param bridge Bridge contract address
     * @param authorized Authorization status
     */
    function authorizeBridge(address bridge, bool authorized) external onlyOwner {
        authorizedBridges[bridge] = authorized;
        emit BridgeAuthorized(bridge, authorized);
    }
    
    /**
     * @dev Pause token transfers (emergency only)
     */
    function pause() external onlyOwner {
        _pause();
    }
    
    /**
     * @dev Unpause token transfers
     */
    function unpause() external onlyOwner {
        _unpause();
    }
    
    /**
     * @dev Override transfer functions to include pause functionality
     */
    function _beforeTokenTransfer(address from, address to, uint256 amount)
        internal
        whenNotPaused
        override
    {
        super._beforeTokenTransfer(from, to, amount);
    }
    
    /**
     * @dev Emergency withdraw function (in case of accidental ETH/token deposits)
     */
    function emergencyWithdraw(address token, uint256 amount) external onlyOwner {
        if (token == address(0)) {
            payable(owner()).transfer(amount);
        } else {
            IERC20(token).transfer(owner(), amount);
        }
    }
    
    /**
     * @dev Get token information for exchanges
     */
    function getTokenInfo() external view returns (
        string memory tokenName,
        string memory tokenSymbol,
        uint8 tokenDecimals,
        uint256 currentSupply,
        uint256 maxSupply,
        address bridge
    ) {
        return (
            name(),
            symbol(),
            decimals(),
            totalSupply(),
            MAX_SUPPLY,
            bridgeContract
        );
    }
}