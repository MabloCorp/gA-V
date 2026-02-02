#!/bin/bash

wget https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip
unzip yara-forge-rules-full.zip

wget https://yaraify.abuse.ch/yarahub/yaraify-rules.zip
unzip yaraify-rules.zip -d yaraify



# Define the base URL of your application
BASE_URL="http://127.0.0.1:8080"

# Function to recompile YARA rules
recompile_rules() {
    echo "Requesting to recompile YARA rules..."
    curl -X POST "$BASE_URL/recompile"
    echo ""
}

# Function to reload the hash list
reload_hashes() {
    echo "Requesting to reload hash list..."
    curl -X POST "$BASE_URL/reload_hash"
    echo ""
}

# Main script logic
# You can uncomment the function you want to use or run them sequentially.

# Recompile YARA rules
recompile_rules

# Reload hashes
reload_hashes




rm yara-forge-rules-full.zip
rm yaraify-rules.zip