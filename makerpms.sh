#!/usr/bin/bash
set -o errexit

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

pushd "${DIR}"
test ! -x "${DIR}/configure" && autoreconf -i
test ! -f "${DIR}/Makefile" && ./configure "$@"
make rpms
popd
