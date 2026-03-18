#!/bin/bash

wget https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip
unzip yara-forge-rules-full.zip

wget https://yaraify.abuse.ch/yarahub/yaraify-rules.zip
unzip yaraify-rules.zip -d yaraify

wget https://bazaar.abuse.ch/export/txt/sha256/full
unzip full
export SHA_FILE=full_sha256.txt
tail -n +10 "$SHA_FILE" > "$SHA_FILE.tmp" && mv "$SHA_FILE.tmp" "$SHA_FILE"
head -n -2  "$SHA_FILE" > "$SHA_FILE.tmp" && mv "$SHA_FILE.tmp" "$SHA_FILE"

rm yara-forge-rules-full.zip
rm yaraify-rules.zip
rm full
