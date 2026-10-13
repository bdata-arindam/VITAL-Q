#!/usr/bin/env bash
set -euo pipefail
# Build outside measurement periods. Use a fresh directory.
TASK_BUILD_ROOT="${1:?Specify a fresh absolute build directory}"
mkdir -p "$TASK_BUILD_ROOT"
git clone https://github.com/open-quantum-safe/liboqs.git "$TASK_BUILD_ROOT/liboqs"
git -C "$TASK_BUILD_ROOT/liboqs" checkout 5a1a854b0dc9f2141bdc771c555ee60c37950183
cmake -S "$TASK_BUILD_ROOT/liboqs" -B "$TASK_BUILD_ROOT/build" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_DIST_BUILD=ON -DOQS_USE_OPENSSL=OFF '-DOQS_MINIMAL_BUILD=SIG_ml_dsa_65;SIG_slh_dsa_pure_sha2_192f' -DCMAKE_INSTALL_PREFIX="$TASK_BUILD_ROOT/install"
cmake --build "$TASK_BUILD_ROOT/build" -j 4
cmake --install "$TASK_BUILD_ROOT/build"
echo 'Set OQS_INSTALL_PATH to the install directory before importing oqs.'
