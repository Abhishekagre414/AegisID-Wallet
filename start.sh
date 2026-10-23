#!/bin/bash
echo "========================================================"
echo "  AegisID: Decentralized Identity (DID) & VC Platform"
echo "========================================================"
echo ""
echo "[1/2] Building latest production assets..."
npm run build
if [ $? -ne 0 ]; then
    echo "Error building frontend assets."
    exit 1
fi
echo ""
echo "[2/2] Starting Unified Full-Stack Production Server..."
echo "Application will be available at: http://localhost:5000"
echo ""
npm start
