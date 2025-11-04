# BlackHole Blockchain Batch Scripts

This folder contains all the Windows batch (.bat) files for the BlackHole Blockchain project. These scripts provide convenient one-click execution for various project operations.

## 🚀 Quick Start Scripts

### `quick-start.bat`
- **Purpose**: Fastest way to start the entire BlackHole ecosystem
- **What it does**: Starts blockchain, bridge SDK, and all dashboards
- **Usage**: Double-click or run from command line
- **Recommended for**: First-time users and quick demos

### `start_blockchain.bat`
- **Purpose**: Start only the main BlackHole blockchain node
- **What it does**: Launches the core blockchain on port 3000
- **Usage**: For blockchain-only operations
- **Recommended for**: Development and testing

## 🌉 Bridge & Production Scripts

### `start_production.bat`
- **Purpose**: Start production-ready BlackHole blockchain with bridge
- **What it does**: Launches blockchain with bridge SDK integration
- **Usage**: For production deployments
- **Recommended for**: Live environments

### `stop_production.bat`
- **Purpose**: Safely stop all production services
- **What it does**: Gracefully shuts down blockchain and bridge services
- **Usage**: Companion to start_production.bat
- **Recommended for**: Clean shutdowns

## 🎛️ Dashboard Scripts

### `start_all_dashboards.bat`
- **Purpose**: Launch all monitoring and management dashboards
- **What it does**: Opens blockchain, bridge, and monitoring interfaces
- **Usage**: For comprehensive system monitoring
- **Recommended for**: Operations and monitoring

## 💰 Wallet Scripts

### `start_wallet.bat`
- **Purpose**: Start the BlackHole wallet CLI interface
- **What it does**: Launches command-line wallet operations
- **Usage**: For wallet management and transactions
- **Recommended for**: Advanced users

### `start_wallet_web.bat`
- **Purpose**: Start the web-based wallet interface
- **What it does**: Launches wallet web UI on browser
- **Usage**: For user-friendly wallet operations
- **Recommended for**: General users

## 🚢 Deployment Scripts

### `deploy.bat`
- **Purpose**: Full deployment with all components
- **What it does**: Deploys blockchain, bridge, and all services
- **Usage**: For complete system deployment
- **Recommended for**: Initial setup

### `deploy-simple.bat`
- **Purpose**: Simplified deployment for basic setup
- **What it does**: Minimal deployment with core components
- **Usage**: For lightweight deployments
- **Recommended for**: Testing and development

## 🔍 Monitoring Scripts

### `health_check.bat`
- **Purpose**: Check system health and status
- **What it does**: Runs health checks on all components
- **Usage**: For system diagnostics
- **Recommended for**: Troubleshooting

## 📝 Usage Instructions

1. **Navigate to this folder**: `cd scripts/batch-files`
2. **Run any script**: Double-click or use command line
3. **Follow prompts**: Most scripts provide interactive guidance
4. **Check logs**: Monitor console output for status updates

## 🔧 Troubleshooting

- **Permission Issues**: Run as Administrator if needed
- **Port Conflicts**: Check if ports 3000, 8080, 8084 are available
- **Database Locks**: Stop all processes before restarting
- **Network Issues**: Ensure firewall allows required ports

## 📁 File Organization

All batch files have been moved here to maintain a clean root directory structure while keeping them easily accessible for operations.

## 🔗 Related Documentation

- Main README: `../../README.md`
- API Documentation: `../../docs/API_DOCUMENTATION.md`
- Production Guide: `../../docs/PRODUCTION_DEPLOYMENT_GUIDE.md`
