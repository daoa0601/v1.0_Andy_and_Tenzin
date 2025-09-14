#!/bin/bash

echo "--- SiFT Project Initializer ---"

# Step 1: Install dependencies
echo "[1] Installing required Python packages from requirements.txt..."
if command -v pip3 &> /dev/null; then
    pip3 install -r requirements.txt
elif command -v pip &> /dev/null; then
    pip install -r requirements.txt
else
    echo "Error: pip is not installed. Please install pip to continue."
    exit 1
fi

echo ""
echo "Installation complete."
echo ""

# Step 2: Provide instructions to run the server and client
echo "[2] Instructions to run the application:"
echo ""
echo "You will need two separate terminal windows to run the server and the client."
echo ""
echo "--- In your FIRST terminal, run the server: ---"
echo "python3 server.py"
echo ""
echo "--- In your SECOND terminal, run the client: ---"
echo "python3 client.py"
echo ""
echo "The project is now set up. You can run the server and client using the commands above."

# Make the script executable
chmod +x start.sh
