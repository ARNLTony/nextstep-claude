#!/bin/sh
# Fetch Crypto Ancienne TLS library
# https://github.com/classilla/cryanc

REPO="https://raw.githubusercontent.com/classilla/cryanc/master"

echo "Fetching Crypto Ancienne..."

if command -v curl >/dev/null 2>&1; then
    curl -sL "$REPO/cryanc.c" -o cryanc.c
    curl -sL "$REPO/cryanc.h" -o cryanc.h
elif command -v wget >/dev/null 2>&1; then
    wget -q "$REPO/cryanc.c" -O cryanc.c
    wget -q "$REPO/cryanc.h" -O cryanc.h
else
    echo "Error: need curl or wget to fetch cryanc"
    exit 1
fi

echo "Downloaded cryanc.c ($(wc -c < cryanc.c) bytes)"
echo "Downloaded cryanc.h ($(wc -c < cryanc.h) bytes)"
echo "Done. Now transfer these files to the NeXT and compile."
