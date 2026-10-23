@echo off
title AegisID - Decentralized Identity Wallet
echo ========================================================
echo   AegisID: Decentralized Identity (DID) & VC Platform
echo ========================================================
echo.
echo [1/2] Building latest production assets...
call npm.cmd run build
if %errorlevel% neq 0 (
    echo Error building frontend assets.
    pause
    exit /b %errorlevel%
)
echo.
echo [2/2] Starting Unified Full-Stack Production Server...
echo Application will be available at: http://localhost:5000
echo.
call npm.cmd start
pause
