#!/bin/sh
# Build NetScanner.jar (needs JDK 8 or newer)
cd "$(dirname "$0")"
rm -rf out && mkdir out
javac -encoding UTF-8 -d out src/netscanner/*.java || exit 1
printf 'Main-Class: netscanner.Main\n' > out/manifest.txt
jar cfm NetScanner.jar out/manifest.txt -C out netscanner
echo "Built NetScanner.jar"
