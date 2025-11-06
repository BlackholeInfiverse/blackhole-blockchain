# BlackHole Mainnet Deployment Guide

This guide describes how to deploy the BlackHole blockchain node, dashboard, and bridge to production with a persistent libp2p identity, TLS, secrets management, backups, and monitoring.

---

## 1) Architecture Overview

- Blockchain (core/relay-chain)
  - P2P: libp2p over TCP
  - Persistent identity: stored under `/data/blockchain/identity/key.pem`
  - Dashboard/API: port 8080
  - Data store: LevelDB (embedded, per-node) e.g., `blockchaindb_3000`
- Bridge SDK (bridge-sdk)
  - API/Dashboard: port 8084
  - Data store: BoltDB (embedded, file) e.g., `/app/data/bridge_v4.db`
  - Reads shared identity info via a read-only mount: `/data/blockchain/identity/peerinfo.json`
- Optional Wallet service (not part of the main compose):
  - PostgreSQL (primary if available) + Redis (cache) + BadgerDB fallback

---

## 2) Prerequisites

- Docker and Docker Compose installed
- DNS entries for your public domain(s)
  - Example: `node.blackhole.example.com` (dashboard 8080)
  - Example: `bridge.blackhole.example.com` (bridge 8084)
- Public firewall rules allowing (as applicable):
  - 80/443 (HTTP/HTTPS)
  - 8080 (Blockchain dashboard/API) — preferably behind reverse proxy
  - 8084 (Bridge dashboard/API) — preferably behind reverse proxy
  - 30303 (P2P on host; mapped to container’s 3000)

---

## 3) Deploy with Docker Compose

The top-level `docker-compose.yml` runs:
- `blockchain-node-1` (dashboard on 8080, P2P mapped to 30303)
- `bridge` (dashboard on 8084)
- A persistent shared volume `blockchain_data` mounted at `/data/blockchain`

This ensures the blockchain’s libp2p identity remains stable across restarts and is visible to the bridge (read-only).

### Steps

1. Build and start

   ```bash
   docker compose up -d --build
   ```

2. Verify services

   - Check containers:
     ```bash
     docker compose ps
     ```
   - Tail logs:
     ```bash
     docker compose logs -f blockchain-node-1 bridge
     ```

3. Confirm persistent identity

   - On the host volume (managed by Docker), the container mounts `blockchain_data:/data/blockchain`.
   - Inside the blockchain container:
     ```bash
     docker exec -it blackhole-node-1 sh -lc 'ls -la /data/blockchain/identity && cat /data/blockchain/identity/peerinfo.json'
     ```
   - The `peerinfo.json` includes:
     ```json
     {
       "peerId": "12D3Koo...",
       "multiaddrs": ["/ip4/127.0.0.1/tcp/3000/p2p/12D3Koo..."],
       "lastSeen": "..."
     }
     ```

4. Access dashboards

   - Blockchain: http://localhost:8080
   - Bridge: http://localhost:8084

---

## 4) Token, Coin, and Valuation Configuration

- Native token BHX is initialized in `core/relay-chain/chain/blockchain.go`:
  - Max supply and circulating supply mechanics are defined there.
  - Block reward (`bc.BlockReward`) controls emission per mined block.
- For production economics:
  - Adjust initial distributions and rewards in code (and re-build) or introduce configuration flags/env vars if you plan to manage these dynamically.
  - Maintain backward compatibility with existing token registry and accounting logic.
- Valuation systems (fiat, oracles):
  - If external price oracles are needed, integrate read-only endpoints and cache values server-side (outside scope of current repo). Keep token accounting on-chain unchanged.

---

## 5) Bridge Configuration

- The bridge reads its DB path from `DATABASE_PATH` (defaults to `/app/data/bridge_v4.db` in compose).
- Configure external chain RPC endpoints via env vars (see `bridge-sdk/example/.env.example`):
  - ETHEREUM_RPC / SOLANA_RPC (and/or *_WS_URL)
- The bridge can discover the blockchain node’s identity via the shared read-only mount:
  - `/data/blockchain/identity/peerinfo.json`
- Ensure bridge health at: `http://<bridge-host>:8084/health`

---

## 6) Hosting, TLS, and Reverse Proxy

Place blockchain and bridge behind an HTTPS reverse proxy (Nginx, Caddy, or Traefik).

### Example: Nginx

- Install certbot + nginx plugin (or use your preferred TLS solution).
- Sample server blocks:

  ```nginx
  server {
    listen 80;
    server_name node.blackhole.example.com;
    return 301 https://$host$request_uri;
  }
  server {
    listen 443 ssl http2;
    server_name node.blackhole.example.com;
    ssl_certificate     /etc/letsencrypt/live/node.blackhole.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/node.blackhole.example.com/privkey.pem;

    location / {
      proxy_pass http://127.0.0.1:8080;
      proxy_set_header Host $host;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto https;
    }
  }

  server {
    listen 80;
    server_name bridge.blackhole.example.com;
    return 301 https://$host$request_uri;
  }
  server {
    listen 443 ssl http2;
    server_name bridge.blackhole.example.com;
    ssl_certificate     /etc/letsencrypt/live/bridge.blackhole.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/bridge.blackhole.example.com/privkey.pem;

    location / {
      proxy_pass http://127.0.0.1:8084;
      proxy_set_header Host $host;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto https;
    }
  }
  ```

- Obtain certificates (example):
  ```bash
  sudo certbot --nginx -d node.blackhole.example.com -d bridge.blackhole.example.com
  ```

### Example: Caddy (simple)

  ```caddyfile
  node.blackhole.example.com {
    reverse_proxy 127.0.0.1:8080
  }
  bridge.blackhole.example.com {
    reverse_proxy 127.0.0.1:8084
  }
  ```

Caddy provisions and renews certificates automatically.

---

## 7) Security and Secrets

- Use Docker secrets or an external secrets manager (AWS KMS/Secrets Manager, GCP KMS/Secret Manager, HashiCorp Vault) for:
  - Any external RPC keys (ETH, SOL)
  - Wallet service credentials (if used)
  - JWT/API keys
- Do not bake secrets into images or commit them to Git.
- libp2p private key is stored at `/data/blockchain/identity/key.pem` (volume). Protect host volume permissions.
- Rotate external keys periodically and roll restarts with minimal downtime.
- Restrict inbound traffic at the firewall (allow only necessary public ports; limit management ports to VPN/admin subnets).

---

## 8) Backups and Disaster Recovery

- Blockchain node (LevelDB):
  - Snapshot the `blockchaindb_3000` directory regularly (filesystem snapshots recommended).
  - Consider scheduled offline backups; avoid copying while the process is writing. If using live backups, use LVM/ZFS snapshots or pause the container briefly.
- Bridge (BoltDB):
  - Backup `/app/data/bridge_v4.db` on a schedule.
- Identity:
  - Backup `/data/blockchain/identity/` (key.pem + peerinfo.json). This is critical to preserve the persistent peer ID.
- Offsite storage:
  - Store encrypted backups offsite; test restore procedures regularly.

---

## 9) Monitoring and Health Checks

- Health endpoints:
  - Blockchain dashboard/API: `http://<host>:8080/api/health`
  - Bridge: `http://<host>:8084/health`
- Logs:
  - Stream via: `docker compose logs -f blockchain-node-1 bridge`
- Alerts:
  - Create uptime checks for the health endpoints.
  - Optionally ship logs to a centralized system (e.g., Loki/ELK) with structured logging.
- Capacity:
  - Monitor disk usage for volumes (identity, LevelDB, BoltDB) and rotate/expand as needed.

---

## 10) Operations and Maintenance Checklist

- [ ] Keep Docker images up-to-date and rebuild on dependency updates.
- [ ] Maintain reverse proxy & TLS certificates (auto-renew)
- [ ] Review logs and alerts daily
- [ ] Backup LevelDB, BoltDB, and identity volume on schedule
- [ ] Test restores monthly
- [ ] Rotate external RPC/API keys and secrets regularly
- [ ] Apply OS and container host security updates
- [ ] Validate P2P peer address remains stable across restarts

---

## 11) Rollouts and Zero-Downtime Tips

- Use `docker compose pull && docker compose up -d` to roll new images.
- For breaking blockchain parameter changes, coordinate a maintenance window.
- Always verify identity persistence before and after deploys:
  - Confirm `peerinfo.json` and `key.pem` remain unchanged.

---

## 12) Troubleshooting

- Dashboard not reachable:
  - Check container health (`docker compose ps`) and logs.
  - Verify reverse proxy config and certificates.
- Bridge unhealthy:
  - Inspect bridge logs for RPC connectivity issues.
  - Confirm `DATABASE_PATH` and file permissions are valid.
- Peer address changed after restart:
  - Ensure the identity volume is mounted at `/data/blockchain` and writable for the blockchain container.
  - Confirm `/data/blockchain/identity/key.pem` exists and persists between restarts.

---

## 13) References

- Blockchain entrypoint: `core/relay-chain/cmd/relay/main.go`
- Bridge entrypoint: `bridge-sdk/main_bridge/main.go`
- Compose file: `docker-compose.yml`
- Identity files (in-container): `/data/blockchain/identity/key.pem`, `/data/blockchain/identity/peerinfo.json`
