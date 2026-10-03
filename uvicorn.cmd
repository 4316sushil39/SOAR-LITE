@echo off
"%~dp0.venv\Scripts\python.exe" -m uvicorn %*
exit /b %errorlevel%
