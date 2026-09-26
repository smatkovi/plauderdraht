#!/bin/sh
# Baut den Plauderdraht fuer das N9/N950 auf dem Build-Rechner.
set -e
cd "$(dirname "$0")/.."
FERN=/tmp/plauderdraht-src
HOST=$(sh "$HOME/ps/nfsshift-sfos/tools/buildhost.sh")
echo "== Build-Rechner: $HOST"
rsync -a --delete --exclude build --exclude target --exclude .git ./ "$HOST:$FERN/"
ssh "$HOST" 'sh /tmp/plauderdraht-src/tools/remote-build.sh'
mkdir -p build
scp -q "$HOST:$FERN/build/plauderdraht" build/
echo "== plauderdraht fertig ($(stat -c %s build/plauderdraht) B)"
