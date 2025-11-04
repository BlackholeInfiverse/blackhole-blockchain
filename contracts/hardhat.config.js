require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.19",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  networks: {
<<<<<<< HEAD
    // Ethereum Mainnet
    ethereum: {
=======
    // Polygon Mainnet (CHEAP - ~$0.10 deployment)
    polygon: {
      url: "https://polygon-rpc.com/",
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
      gasPrice: 30000000000, // 30 gwei
    },
    // BSC Mainnet (CHEAP - ~$1 deployment)
    bsc: {
      url: "https://bsc-dataseed1.binance.org/",
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
      gasPrice: 5000000000, // 5 gwei
    },
    // Ethereum Mainnet (EXPENSIVE - $50-150 deployment)
    mainnet: {
>>>>>>> f4c74d1830240c7b0b17c3a1603f76bcea22d04a
      url: process.env.ETHEREUM_RPC_URL || "https://eth-mainnet.g.alchemy.com/v2/your-api-key",
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
      gasPrice: 20000000000, // 20 gwei
    },
<<<<<<< HEAD
    
=======
>>>>>>> f4c74d1830240c7b0b17c3a1603f76bcea22d04a
    // Ethereum Sepolia Testnet
    sepolia: {
      url: process.env.SEPOLIA_RPC_URL || "https://eth-sepolia.g.alchemy.com/v2/your-api-key",
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
<<<<<<< HEAD
      gasPrice: 20000000000, // 20 gwei
    },
    
    // BSC Mainnet
    bsc: {
      url: process.env.BSC_RPC_URL || "https://bsc-dataseed1.binance.org/",
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
      gasPrice: 5000000000, // 5 gwei
    },
    
    // BSC Testnet
    bscTestnet: {
      url: process.env.BSC_TESTNET_RPC_URL || "https://data-seed-prebsc-1-s1.binance.org:8545/",
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
      gasPrice: 10000000000, // 10 gwei
    },
    
    // Polygon Mainnet
    polygon: {
      url: process.env.POLYGON_RPC_URL || "https://polygon-rpc.com/",
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
      gasPrice: 30000000000, // 30 gwei
    },
    
=======
      gasPrice: 10000000000, // 10 gwei
    },
    // Polygon Amoy Testnet (FREE) - New Polygon testnet
    amoy: {
      url: "https://rpc-amoy.polygon.technology/",
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
      gasPrice: 30000000000, // 30 gwei (minimum required)
    },
    // Polygon Mumbai Testnet (FREE) - Legacy
    mumbai: {
      url: "https://rpc-mumbai.maticvigil.com/",
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
      gasPrice: 10000000000, // 10 gwei
    },
    // BSC Mainnet (for multi-chain deployment)
    bsc: {
      url: "https://bsc-dataseed1.binance.org/",
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
      gasPrice: 5000000000, // 5 gwei
    },
    // Polygon Mainnet (for multi-chain deployment)
    polygon: {
      url: "https://polygon-rpc.com/",
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
      gasPrice: 30000000000, // 30 gwei
    },
>>>>>>> f4c74d1830240c7b0b17c3a1603f76bcea22d04a
    // Local development
    localhost: {
      url: "http://127.0.0.1:8545",
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
    },
  },
<<<<<<< HEAD
  
=======
>>>>>>> f4c74d1830240c7b0b17c3a1603f76bcea22d04a
  etherscan: {
    apiKey: {
      mainnet: process.env.ETHERSCAN_API_KEY,
      sepolia: process.env.ETHERSCAN_API_KEY,
      bsc: process.env.BSCSCAN_API_KEY,
<<<<<<< HEAD
      bscTestnet: process.env.BSCSCAN_API_KEY,
      polygon: process.env.POLYGONSCAN_API_KEY,
    },
  },
  
=======
      polygon: process.env.POLYGONSCAN_API_KEY,
    },
  },
>>>>>>> f4c74d1830240c7b0b17c3a1603f76bcea22d04a
  gasReporter: {
    enabled: process.env.REPORT_GAS !== undefined,
    currency: "USD",
  },
<<<<<<< HEAD
  
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts",
  },
  
  mocha: {
    timeout: 40000,
  },
};
=======
};
>>>>>>> f4c74d1830240c7b0b17c3a1603f76bcea22d04a
