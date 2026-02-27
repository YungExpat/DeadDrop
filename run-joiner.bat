@echo off
REM Intercom Joiner Peer Startup Script
REM Replace PEER_NAME and SUBNET_BOOTSTRAP_HEX with actual values from the admin peer

REM Get the admin peer's subnet bootstrap from:
REM stores/admin/subnet-bootstrap.hex (after first admin run)

setlocal enabledelayedexpansion
set PEER_NAME=%1
set SUBNET_BOOTSTRAP=%2

if "!PEER_NAME!"=="" (
  echo Usage: run-joiner.bat PEER_NAME SUBNET_BOOTSTRAP_HEX
  echo.
  echo Example: run-joiner.bat peer1 a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f
  pause
  exit /b 1
)

if "!SUBNET_BOOTSTRAP!"=="" (
  echo Error: SUBNET_BOOTSTRAP_HEX required
  echo.
  echo Get the subnet bootstrap from the admin peer:
  echo 1. Check stores/admin/subnet-bootstrap.hex
  echo 2. Or run the admin and copy the hex output
  pause
  exit /b 1
)

pear run . ^
  --peer-store-name !PEER_NAME! ^
  --msb-store-name !PEER_NAME!-msb ^
  --subnet-channel DropDead ^
  --subnet-bootstrap !SUBNET_BOOTSTRAP! ^
  --dht-bootstrap "bootstrap1.holepunch.to:49736,bootstrap2.holepunch.to:49736,bootstrap3.holepunch.to:49736"

pause
