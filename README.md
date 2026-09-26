# Plauderdraht — STARTTLS für Harmattans XMPP-Konto

Harmattans `telepathy-gabble` bringt einen OpenSSL-Stand von 2011 mit und
kommt an keinen Jabber-Server mehr heran, der TLS 1.2 verlangt. Das Konto
zeigt deshalb auf `localhost:5223`, und dort sitzt dieser Draht: er nimmt
die Verbindung im Klartext an, baut selbst eine zum echten Server auf,
handelt dort STARTTLS aus und reicht danach nur noch Bytes durch.

Für gabble sieht das aus wie ein Server ohne Verschlüsselung auf dem
eigenen Gerät; nach außen geht eine heutige TLS-Verbindung.

## Was er tut, Schritt für Schritt

1. Den Servernamen aus dem eingerichteten Jabber-Konto holen (`mc-tool`,
   Zeile `Normalized:` → der Teil hinter dem `@`). Wer ihn selbst weiß,
   gibt ihn als Aufrufparameter mit.
2. Auf `127.0.0.1:5223` horchen, eine Sitzung zur Zeit — gabble hält
   genau eine.
3. Zum Server auf Port 5222 verbinden, den Stromkopf schicken, bis
   `</stream:features>` lesen, auf `<starttls` prüfen.
4. `<starttls/>` schicken, auf `<proceed` warten, TLS aufbauen.
5. Durchreichen. Passiert 300 s lang nichts, geht ein Leerzeichen an den
   Klienten — dasselbe Lebenszeichen, das XMPP selbst benutzt.

Gesucht wird in den Bytes, nicht mit einem XML-Zerleger: der Stromkopf
ist zu dem Zeitpunkt noch gar kein vollständiges Dokument.

## Das Zertifikat wird nicht geprüft

Wie in der Python-Vorlage (`CERT_NONE`). Das ist hier vertretbar und
anderswo nicht: der Draht läuft auf **demselben Gerät** wie der Klient,
die Verbindung zwischen beiden verlässt das Gerät nie, und die Alternative
wäre nicht etwa geprüftes TLS, sondern gar keine Verbindung — die
Wurzelliste von 2011 kennt die heutigen Aussteller nicht.

## Einspielen

    sh tools/build.sh        # -> build/plauderdraht (armel, statisch gegen musl)
    cp build/plauderdraht wurzel/opt/plauderdraht/
    python3 build-deb.py     # -> plauderdraht_1.0_armel.deb

Aufs Gerät mit **`aegis-dpkg -i`**, nicht `dpkg -i`.

Das Paket bringt einen Upstart-Job unter `/etc/init/apps` mit und legt
`/etc/init/xmpp-proxy.override` (`manual`) daneben, damit der Vorgänger
nicht um Port 5223 streitet; das `postinst` beendet ihn zusätzlich für
den laufenden Betrieb.

Der Job läuft als nackter root ohne Sitzung. `mc-tool` braucht aber eine:
der Draht liest die Adresse deshalb selbst aus
`/tmp/session_bus_address.user` — dort steht die **aktuelle**, während das
Absuchen von `/proc` gern eine Leiche aus einer früheren Sitzung liefert.

## Nachsehen

Ohne gabble prüfen lässt er sich mit einem rohen Stromkopf:

    python -c "
    import socket
    s=socket.socket(); s.connect(('127.0.0.1',5223))
    s.send(\"<?xml version='1.0'?><stream:stream to='DEINE.DOMAIN' \
    xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' \
    version='1.0'>\")
    print s.recv(4096)[:200]"

Kommt ein `<stream:stream … from='DEINE.DOMAIN'>` zurück, steht alles bis
einschließlich TLS.

## Geschichte

Vorlage ist `xmpp-proxy.py` (liegt unter `alt/`), das mit dem
pybridge-Paket kam: 0,9 MB belegter Arbeitsspeicher plus eine
`while true`-Schleife drumherum. Der Draht belegt 268 kB und wird von
Upstart selbst am Leben gehalten.

Lizenz: GPL-3.0-or-later.
