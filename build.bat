@echo off
cd /d "%~dp0"
if exist out rmdir /s /q out
mkdir out
javac -encoding UTF-8 -d out src\netscanner\*.java || exit /b 1
echo Main-Class: netscanner.Main> out\manifest.txt
jar cfm NetScanner.jar out\manifest.txt -C out netscanner
echo Built NetScanner.jar
