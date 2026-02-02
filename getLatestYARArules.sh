#!/bin/bash

wget https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip
unzip yara-forge-rules-full.zip

wget https://yaraify.abuse.ch/yarahub/yaraify-rules.zip
unzip yaraify-rules.zip -d yaraify


rm yara-forge-rules-full.zip
rm yaraify-rules.zip
