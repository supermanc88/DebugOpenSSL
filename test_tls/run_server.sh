#!/bin/bash
cd "$(dirname "$0")"
export DYLD_LIBRARY_PATH="../openssl-3.5.2:$DYLD_LIBRARY_PATH"
./test_tls server
