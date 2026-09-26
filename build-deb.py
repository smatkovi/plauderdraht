#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Baut plauderdraht_<version>_armel.deb aus wurzel/.

Die Falle, die hier alles kostet: Harmattans dpkg-deb und sein tar sind von
2011 und lesen **kein** PAX. Pythons tarfile schreibt seit 3.8 aber PAX, und
die 'x'-Kopfsaetze quittiert das Geraet mit "corrupted package archive".
Deshalb ueberall ausdruecklich GNU_FORMAT.
"""

import hashlib
import os
import subprocess
import sys
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "wurzel")

VERSION = "1.0.1"
CONTROL = """Package: plauderdraht
Version: %s
Architecture: armel
Maintainer: Sebastian <user@localhost>
Depends: telepathy-mission-control-5
Section: user/other
Priority: extra
Description: STARTTLS-Draht fuer Harmattans XMPP-Konto
 Harmattans gabble bringt einen OpenSSL-Stand von 2011 mit und kommt an
 keinen Server mehr heran, der TLS 1.2 verlangt. Das Jabber-Konto zeigt
 deshalb auf localhost:5223, und dort sitzt dieser Draht: er nimmt die
 Verbindung im Klartext an, baut selbst eine zum echten Server auf,
 handelt STARTTLS aus und reicht danach nur Bytes durch.
 .
 Loest xmpp-proxy.py ab (aus dem pybridge-Paket): 0,9 MB Python werden zu
 rund 0,2 MB. Dieselbe Mechanik, dieselben Bytemuster, dasselbe
 Leerzeichen-Lebenszeichen alle 300 s. Den Servernamen holt der Draht aus
 dem eingerichteten Jabber-Konto (mc-tool), oder er nimmt ihn als
 Aufrufparameter.
 .
 Das Serverzertifikat wird wie vorher nicht geprueft: der Draht laeuft auf
 demselben Geraet wie der Klient, und die Wurzelliste von 2011 kennt die
 heutigen Aussteller nicht.
 .
 WICHTIG beim Einspielen von Hand: mit "aegis-dpkg -i" installieren.
""" % VERSION

POSTINST = """#!/bin/sh
# Der Vorgaenger haelt Port 5223; ohne ihn anzuhalten kommt der Draht
# nicht hoch. Sein Upstart-Job liegt in /etc/init und laesst sich nicht
# lesen (aegis), abgestellt wird er deshalb ueber die .override-Datei --
# die greift beim naechsten Start, der laufende Prozess hier und jetzt.
for p in $(ps ax 2>/dev/null | grep "[x]mpp-proxy.py" | awk '{print $1}'); do
    kill $p 2>/dev/null || true
done
start apps/plauderdraht 2>/dev/null || true
exit 0
"""

PRERM = """#!/bin/sh
# Abgekoppelt: ein einmal verklemmter Upstart-Job laesst "stop" ewig
# haengen, und ein dpkg, das im prerm haengt, blockiert die ganze
# Paketverwaltung.
( stop apps/plauderdraht >/dev/null 2>&1 & )
exit 0
"""


def gnu_tar(ziel, eintraege):
    with tarfile.open(ziel, "w:gz", format=tarfile.GNU_FORMAT) as tar:
        for pfad, name, mode in eintraege:
            info = tar.gettarinfo(pfad, name)
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mode = mode
            if info.isdir():
                tar.addfile(info)
            else:
                with open(pfad, "rb") as f:
                    tar.addfile(info, f)


def sammeln():
    """Alles unter wurzel/, Verzeichnisse vor ihren Dateien."""
    eintraege = []
    for wurzel, verzeichnisse, dateien in os.walk(ROOT):
        verzeichnisse.sort()
        for name in [""] + sorted(dateien):
            pfad = os.path.join(wurzel, name) if name else wurzel
            rel = os.path.relpath(pfad, ROOT)
            if rel == ".":
                continue
            mode = 0o755 if os.path.isdir(pfad) or os.access(pfad, os.X_OK) else 0o644
            eintraege.append((pfad, "./" + rel, mode))
    return eintraege


def md5sums(eintraege):
    zeilen = []
    for pfad, name, _ in eintraege:
        if os.path.isdir(pfad):
            continue
        with open(pfad, "rb") as f:
            zeilen.append("%s  %s\n" % (hashlib.md5(f.read()).hexdigest(), name[2:]))
    return "".join(zeilen)


def main():
    binaer = os.path.join(ROOT, "opt/plauderdraht/plauderdraht")
    if not os.path.exists(binaer):
        sys.exit("wurzel/opt/plauderdraht/plauderdraht fehlt -- erst tools/build.sh")

    eintraege = sammeln()
    bau = os.path.join(HERE, "bau")
    os.makedirs(bau, exist_ok=True)
    for name, inhalt, mode in (("control", CONTROL, 0o644),
                               ("postinst", POSTINST, 0o755),
                               ("prerm", PRERM, 0o755),
                               ("md5sums", md5sums(eintraege), 0o644)):
        pfad = os.path.join(bau, name)
        with open(pfad, "w") as f:
            f.write(inhalt)
        os.chmod(pfad, mode)

    gnu_tar(os.path.join(bau, "control.tar.gz"),
            [(os.path.join(bau, n), "./" + n, m)
             for n, m in (("control", 0o644), ("postinst", 0o755),
                          ("prerm", 0o755), ("md5sums", 0o644))])
    gnu_tar(os.path.join(bau, "data.tar.gz"), eintraege)
    with open(os.path.join(bau, "debian-binary"), "w") as f:
        f.write("2.0\n")

    ziel = os.path.join(HERE, "plauderdraht_%s_armel.deb" % VERSION)
    if os.path.exists(ziel):
        os.remove(ziel)
    subprocess.check_call(["ar", "rc", ziel, "debian-binary",
                           "control.tar.gz", "data.tar.gz"], cwd=bau)
    print("%s %d Bytes" % (ziel, os.path.getsize(ziel)))


if __name__ == "__main__":
    main()
