#!/bin/sh

set -e

# The SmartCard daemon has to started to communicate with plugged in HSM devices
# https://pcsclite.apdu.fr/
pcscd

exec "$@"
