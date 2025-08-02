// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title FraudDetection
 * @dev Smart contract for flagging suspicious wallets and tracking fraud reports
 * @notice This contract integrates with the Blackhole blockchain fraud detection system
 */
contract FraudDetection {
    
    // Struct to store flag information
    struct FlagInfo {
        uint256 timestamp;
        string reporterId;
        string reason;
        uint8 severity; // 1-5 scale
        bool isActive;
    }
    
    // Mapping from wallet address to array of flag reports
    mapping(string => FlagInfo[]) private walletFlags;
    
    // Mapping to track total flag count per wallet
    mapping(string => uint256) private flagCounts;
    
    // Mapping to track unique reporters per wallet (prevent spam)
    mapping(string => mapping(string => bool)) private hasReported;
    
    // Contract owner for administrative functions
    address public owner;
    
    // Events for transparency and off-chain monitoring
    event WalletFlagged(
        string indexed walletAddress,
        string reporterId,
        string reason,
        uint8 severity,
        uint256 timestamp
    );
    
    event FlagRemoved(
        string indexed walletAddress,
        uint256 flagIndex,
        string removedBy,
        uint256 timestamp
    );
    
    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );
    
    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }
    
    modifier validWalletAddress(string memory walletAddress) {
        require(bytes(walletAddress).length > 0, "Wallet address cannot be empty");
        require(bytes(walletAddress).length <= 100, "Wallet address too long");
        _;
    }
    
    modifier validReporterId(string memory reporterId) {
        require(bytes(reporterId).length > 0, "Reporter ID cannot be empty");
        require(bytes(reporterId).length <= 50, "Reporter ID too long");
        _;
    }
    
    modifier validSeverity(uint8 severity) {
        require(severity >= 1 && severity <= 5, "Severity must be between 1 and 5");
        _;
    }
    
    /**
     * @dev Constructor sets the contract deployer as owner
     */
    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), owner);
    }
    
    /**
     * @dev Flag a wallet as suspicious
     * @param walletAddress The wallet address to flag
     * @param reporterId ID of the entity reporting (can be user email, system ID, etc.)
     * @param reason Description of why the wallet is being flagged
     * @param severity Severity level from 1 (low) to 5 (critical)
     * @return success True if flagging was successful
     */
    function flagWallet(
        string memory walletAddress,
        string memory reporterId,
        string memory reason,
        uint8 severity
    ) 
        public 
        validWalletAddress(walletAddress)
        validReporterId(reporterId)
        validSeverity(severity)
        returns (bool success) 
    {
        // Prevent duplicate reports from same reporter for same wallet
        require(
            !hasReported[walletAddress][reporterId], 
            "Reporter has already flagged this wallet"
        );
        
        // Create new flag info
        FlagInfo memory newFlag = FlagInfo({
            timestamp: block.timestamp,
            reporterId: reporterId,
            reason: reason,
            severity: severity,
            isActive: true
        });
        
        // Add flag to wallet's flag array
        walletFlags[walletAddress].push(newFlag);
        
        // Increment flag count
        flagCounts[walletAddress]++;
        
        // Mark reporter as having reported this wallet
        hasReported[walletAddress][reporterId] = true;
        
        // Emit event for off-chain monitoring
        emit WalletFlagged(
            walletAddress,
            reporterId,
            reason,
            severity,
            block.timestamp
        );
        
        return true;
    }
    
    /**
     * @dev Get the total number of times a wallet has been flagged
     * @param walletAddress The wallet address to check
     * @return count Number of active flags for the wallet
     */
    function getReportCount(string memory walletAddress) 
        public 
        view 
        validWalletAddress(walletAddress)
        returns (uint256 count) 
    {
        return flagCounts[walletAddress];
    }
    
    /**
     * @dev Get detailed flag information for a wallet
     * @param walletAddress The wallet address to check
     * @return flags Array of all flag information for the wallet
     */
    function getWalletFlags(string memory walletAddress)
        public
        view
        validWalletAddress(walletAddress)
        returns (FlagInfo[] memory flags)
    {
        return walletFlags[walletAddress];
    }
    
    /**
     * @dev Check if a wallet has been flagged by a specific reporter
     * @param walletAddress The wallet address to check
     * @param reporterId The reporter ID to check
     * @return hasReportedFlag True if the reporter has flagged this wallet
     */
    function hasReporterFlagged(
        string memory walletAddress,
        string memory reporterId
    )
        public
        view
        validWalletAddress(walletAddress)
        validReporterId(reporterId)
        returns (bool hasReportedFlag)
    {
        return hasReported[walletAddress][reporterId];
    }
    
    /**
     * @dev Get the highest severity flag for a wallet
     * @param walletAddress The wallet address to check
     * @return maxSeverity Highest severity level (0 if no flags)
     */
    function getMaxSeverity(string memory walletAddress)
        public
        view
        validWalletAddress(walletAddress)
        returns (uint8 maxSeverity)
    {
        FlagInfo[] memory flags = walletFlags[walletAddress];
        uint8 max = 0;
        
        for (uint256 i = 0; i < flags.length; i++) {
            if (flags[i].isActive && flags[i].severity > max) {
                max = flags[i].severity;
            }
        }
        
        return max;
    }
    
    /**
     * @dev Remove a specific flag (admin function)
     * @param walletAddress The wallet address
     * @param flagIndex Index of the flag to remove
     * @return success True if removal was successful
     */
    function removeFlag(
        string memory walletAddress,
        uint256 flagIndex
    )
        public
        onlyOwner
        validWalletAddress(walletAddress)
        returns (bool success)
    {
        require(flagIndex < walletFlags[walletAddress].length, "Invalid flag index");
        require(walletFlags[walletAddress][flagIndex].isActive, "Flag already inactive");
        
        // Mark flag as inactive
        walletFlags[walletAddress][flagIndex].isActive = false;
        
        // Decrease flag count
        if (flagCounts[walletAddress] > 0) {
            flagCounts[walletAddress]--;
        }
        
        emit FlagRemoved(
            walletAddress,
            flagIndex,
            "admin",
            block.timestamp
        );
        
        return true;
    }
    
    /**
     * @dev Transfer ownership of the contract
     * @param newOwner Address of the new owner
     */
    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
    
    /**
     * @dev Get contract information
     * @return contractOwner Address of the contract owner
     * @return deploymentTime Timestamp when contract was deployed
     */
    function getContractInfo() 
        public 
        view 
        returns (address contractOwner, uint256 deploymentTime) 
    {
        return (owner, block.timestamp);
    }
}
