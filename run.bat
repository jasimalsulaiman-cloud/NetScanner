@echo off
cd /d "%~dp0"
if not exist NetScanner.jar call build.bat
java -jar NetScanner.jar
