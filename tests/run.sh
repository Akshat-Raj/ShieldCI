#!/bin/bash
# detect.sh - Simply detects and outputs the config, does NOT run the app.

if [ -f "Cargo.toml" ]; then
    echo "FRAMEWORK=Rust"
    echo "BUILD_CMD=cargo build"
    echo "RUN_CMD=cargo run"
    echo "TARGET_URL=http://127.0.0.1:8080"

elif [ -f "package.json" ]; then
    echo "FRAMEWORK=Node.js"
    echo "BUILD_CMD=npm install"
    echo "RUN_CMD=npm start"
    echo "TARGET_URL=http://127.0.0.1:3000"

elif [ -f "requirements.txt" ]; then
    echo "FRAMEWORK=Python"
    echo "BUILD_CMD=pip install -r requirements.txt"
    echo "RUN_CMD=python app.py"
    echo "TARGET_URL=http://127.0.0.1:5000"

else
    echo "ERROR=Unrecognized framework. Please provide a Dockerfile."
    exit 1
fi