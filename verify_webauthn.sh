#!/bin/bash
# Verify webauthn library installation
pip3 install webauthn
# Verify database migration
./setup/migrate.py --migrate
# Start daemon
management/daemon.py &
DAEMON_PID=$!
sleep 5
# Test registration begin
curl -X POST -u "admin@example.com:password" http://localhost:10222/mfa/webauthn/register/begin
# Kill daemon
kill $DAEMON_PID
