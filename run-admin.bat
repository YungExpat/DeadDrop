@echo off
REM Intercom Admin Peer Startup Script
REM This script runs the admin peer with public Holepunch bootstrap nodes

pear run . ^
  --peer-store-name admin ^
  --msb-store-name admin-msb ^
  --subnet-channel DropDead ^
  --dht-bootstrap "bootstrap1.holepunch.to:49736,bootstrap2.holepunch.to:49736,bootstrap3.holepunch.to:49736"

pause
