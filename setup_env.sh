#!/bin/bash

echo "--- 1. Updating System Packages ---"
sudo apt-get update && sudo apt-get upgrade -y

echo "--- 2. Installing Python, Git, and Essentials ---"
sudo apt-get install -y python3 python3-pip python3-venv git curl wget ca-certificates gnupg lsb-release

echo "--- 3. Checking for Docker Installation ---"
if ! command -v docker &> /dev/null; then
    echo "Docker not found. Installing Docker Engine..."
    # Add Docker's official GPG key
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    # Set up the repository
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
      $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
else
    echo "Docker is already installed."
fi

echo "--- 4. Configuring Docker Permissions ---"
# This fixes the specific error: "group 'docker' does not exist"
if ! getent group docker > /dev/null; then
    echo "Creating docker group..."
    sudo groupadd docker
fi

echo "Adding user $USER to docker group..."
sudo usermod -aG docker $USER

echo "--- 5. Installing Project Dependencies ---"
pip3 install flask==2.0.1 werkzeug==2.0.3

echo "--- SETUP COMPLETE ---"
echo "IMPORTANT: You must log out and back in (or restart WSL) for Docker permissions to take effect."
