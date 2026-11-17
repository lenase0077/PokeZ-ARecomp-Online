@echo off
cd /d "%~dp0"
echo Starting Lumiose Online Private Server (from saved room config)...
echo Press Ctrl+C to stop the server.
"%~dp0python\python.exe" "%~dp0tools\lumiose\private_server.py" --from-config
pause
