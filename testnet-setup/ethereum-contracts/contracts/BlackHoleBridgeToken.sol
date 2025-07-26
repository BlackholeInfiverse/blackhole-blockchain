// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title BlackHoleBridgeToken
 * @dev ERC-20 token for BlackHole Bridge cross-chain demonstrations
 * 
 * Features:
 * - Standard ERC-20 functionality
 * - Burnable tokens for bridge operations
 * - Pausable for emergency stops
 * - Owner controls for bridge operations
 * - Events for bridge monitoring
 */
contract BlackHoleBridgeToken is ERC20, ERC20Burnable, Ownable, Pausable {
    
    // Bridge-specific events
    event BridgeTransfer(
        address indexed from,
        string indexed destinationChain,
        string destinationAddress,
        uint256 amount,
        bytes32 indexed bridgeId
    );
    
    event BridgeMint(
        address indexed to,
        uint256 amount,
        string indexed sourceChain,
        string sourceTxHash,
        bytes32 indexed bridgeId
    );
    
    // Bridge configuration
    mapping(address => bool) public bridgeOperators;
    mapping(bytes32 => bool) public processedBridgeIds;
    
    uint256 public constant MAX_SUPPLY = 1000000000 * 10**18; // 1 billion tokens
    uint256 public bridgeTransferCount;
    uint256 public bridgeMintCount;
    
    modifier onlyBridgeOperator() {
        require(bridgeOperators[msg.sender] || msg.sender == owner(), "Not authorized bridge operator");
        _;
    }
    
    constructor(
        string memory name,
        string memory symbol,
        uint256 initialSupply
    ) ERC20(name, symbol) Ownable(msg.sender) {
        require(initialSupply <= MAX_SUPPLY, "Initial supply exceeds maximum");
        
        // Mint initial supply to deployer
        _mint(msg.sender, initialSupply);
        
        // Set deployer as initial bridge operator
        bridgeOperators[msg.sender] = true;
    }
    
    /**
     * @dev Initiate a bridge transfer to another chain
     * Burns tokens on this chain and emits bridge event
     */
    function bridgeTransfer(
        string memory destinationChain,
        string memory destinationAddress,
        uint256 amount
    ) external whenNotPaused returns (bytes32 bridgeId) {
        require(amount > 0, "Amount must be greater than 0");
        require(bytes(destinationChain).length > 0, "Destination chain required");
        require(bytes(destinationAddress).length > 0, "Destination address required");
        
        // Generate unique bridge ID
        bridgeId = keccak256(abi.encodePacked(
            block.timestamp,
            block.number,
            msg.sender,
            destinationChain,
            amount,
            bridgeTransferCount++
        ));
        
        // Burn tokens from sender
        _burn(msg.sender, amount);
        
        // Emit bridge event for monitoring
        emit BridgeTransfer(
            msg.sender,
            destinationChain,
            destinationAddress,
            amount,
            bridgeId
        );
        
        return bridgeId;
    }
    
    /**
     * @dev Mint tokens from bridge transfer (called by bridge operators)
     */
    function bridgeMint(
        address to,
        uint256 amount,
        string memory sourceChain,
        string memory sourceTxHash,
        bytes32 bridgeId
    ) external onlyBridgeOperator whenNotPaused {
        require(to != address(0), "Cannot mint to zero address");
        require(amount > 0, "Amount must be greater than 0");
        require(!processedBridgeIds[bridgeId], "Bridge ID already processed");
        require(totalSupply() + amount <= MAX_SUPPLY, "Would exceed maximum supply");
        
        // Mark bridge ID as processed
        processedBridgeIds[bridgeId] = true;
        
        // Mint tokens to recipient
        _mint(to, amount);
        
        // Emit bridge mint event
        emit BridgeMint(
            to,
            amount,
            sourceChain,
            sourceTxHash,
            bridgeId
        );
        
        bridgeMintCount++;
    }
    
    /**
     * @dev Add bridge operator
     */
    function addBridgeOperator(address operator) external onlyOwner {
        bridgeOperators[operator] = true;
    }
    
    /**
     * @dev Remove bridge operator
     */
    function removeBridgeOperator(address operator) external onlyOwner {
        bridgeOperators[operator] = false;
    }
    
    /**
     * @dev Pause contract (emergency stop)
     */
    function pause() external onlyOwner {
        _pause();
    }
    
    /**
     * @dev Unpause contract
     */
    function unpause() external onlyOwner {
        _unpause();
    }
    
    /**
     * @dev Override transfer to add pause functionality
     */
    function _update(address from, address to, uint256 value) internal override whenNotPaused {
        super._update(from, to, value);
    }
    
    /**
     * @dev Get bridge statistics
     */
    function getBridgeStats() external view returns (
        uint256 totalTransfers,
        uint256 totalMints,
        uint256 currentSupply,
        uint256 maxSupply
    ) {
        return (
            bridgeTransferCount,
            bridgeMintCount,
            totalSupply(),
            MAX_SUPPLY
        );
    }
}
