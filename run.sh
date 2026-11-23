#!/bin/sh
cd "$(dirname "$0")"
[ -f NetScanner.jar ] || ./build.sh
java -jar NetScanner.jar
