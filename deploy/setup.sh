#!/bin/bash

# Update system
echo "Updating system packages..."
sudo apt-get update
sudo apt-get upgrade -y

# Install required packages
echo "Installing required packages..."
sudo apt-get install -y \
    git curl wget \
    build-essential pkg-config libssl-dev \
    docker.io docker-compose \
    ufw

# Add user to docker group
echo "Adding current user to docker group..."
sudo usermod -aG docker $USER

# Configure firewall
echo "Configuring firewall..."
sudo ufw allow 22/tcp
sudo ufw allow 8080/tcp
sudo ufw allow 8081/tcp
sudo ufw allow 8545/tcp
sudo ufw allow 8546/tcp
sudo ufw allow 30303/udp
sudo ufw --force enable

# Install Go
if ! command -v go &> /dev/null; then
    echo "Installing Go..."
    wget https://golang.org/dl/go1.19.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.19.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
    echo 'export GOPATH=$HOME/go' >> ~/.profile
    source ~/.profile
    rm go1.19.linux-amd64.tar.gz
fi

# Create project directory
echo "Setting up project directory..."
mkdir -p /opt/blackhole
chown -R $USER:$USER /opt/blackhole

# Create systemd service
echo "Creating systemd service..."
sudo tee /etc/systemd/system/blackhole-bridge.service > /dev/null <<EOL
[Unit]
Description=Blackhole Bridge Service
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/opt/blackhole/blackhole-blockchain/bridge-sdk/main_bridge
ExecStart=/usr/local/go/bin/go run .
Restart=always
Environment=GOPATH=/home/$USER/go
Environment=GOROOT=/usr/local/go
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin

[Install]
WantedBy=multi-user.target
EOL

# Enable and start service
echo "Enabling and starting blackhole-bridge service..."
sudo systemctl daemon-reload
sudo systemctl enable blackhole-bridge
sudo systemctl start blackhole-bridge

echo "Setup complete! The Blackhole Bridge service is now running."
echo "Access the bridge dashboard at: http://localhost:8080"