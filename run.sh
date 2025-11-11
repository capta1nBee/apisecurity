#!/bin/bash

echo "========================================"
echo "API Security Dashboard"
echo "========================================"
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo ""
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate
echo ""

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt
echo ""

# Set environment variables
export FLASK_APP=app.py
export FLASK_ENV=development

# Run the application
echo "========================================"
echo "Starting API Security Dashboard..."
echo "Access the dashboard at: http://localhost:5000"
echo "Press Ctrl+C to stop the server"
echo "========================================"
echo ""

python app.py

