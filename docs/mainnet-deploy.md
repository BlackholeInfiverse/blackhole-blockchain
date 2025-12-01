# Mainnet Deployment Guide

This guide provides step-by-step instructions for deploying the Blackhole Blockchain to mainnet using the prepared documentation and configuration files.

## Prerequisites

- Access to mainnet infrastructure
- All configuration files prepared
- Backup of current state
- Team coordination for deployment

## Directory Structure

Ensure the following directories and files are in place:
- `docs/demo.md` - Demo recording instructions
- `docs/listing-bundle/` - Exchange listing metadata templates
- `data/` - Local node storage directory

## Step-by-Step Deployment

### 1. Environment Preparation

1. Clone the repository to deployment server
2. Copy `.env.example` to `.env` and configure mainnet values
3. Initialize the `data/` directory for local storage:
   ```bash
   mkdir -p data
   chmod 755 data
   ```

### 2. Configuration Validation

1. Review `docs/listing-bundle/token-metadata-template.json` and create actual metadata
2. Update contract addresses in the metadata file
3. Validate all configuration files against schemas

### 3. Node Deployment

1. Start the blockchain node:
   ```bash
   ./start_node.sh
   ```

2. Monitor node synchronization:
   ```bash
   tail -f logs/node.log
   ```

### 4. Bridge Deployment

1. Deploy bridge contracts to mainnet
2. Configure bridge SDK with mainnet endpoints
3. Start bridge services:
   ```bash
   cd bridge-sdk
   docker-compose up -d
   ```

### 5. Monitoring Setup

1. Configure monitoring dashboards
2. Set up alerts for critical metrics
3. Enable logging aggregation

### 6. Testing and Validation

1. Perform smoke tests using `scripts/p2p_smoke.sh`
2. Run swap tests with `scripts/swap_test.sh`
3. Validate bridge functionality

### 7. Demo Preparation

1. Follow instructions in `docs/demo.md` to record deployment demo
2. Prepare showcase materials using listing bundle assets

## Rollback Procedures

If issues arise during deployment:

1. Use `scripts/rollback.sh` for controlled rollback
2. Restore from backup if necessary
3. Document issues and resolutions

## Post-Deployment

1. Update documentation with actual deployed addresses
2. Submit listing bundle to exchanges
3. Announce deployment completion
4. Begin community testing phase

## Security Checklist

- [ ] Private keys secured
- [ ] Access controls configured
- [ ] Firewall rules applied
- [ ] Backup systems operational
- [ ] Monitoring active
- [ ] Incident response plan ready

## Support

For issues during deployment, refer to:
- `docs/demo.md` for demo-specific guidance
- Bridge SDK documentation in `bridge-sdk/docs/`
- Monitoring setup in `bridge-sdk/monitoring/`