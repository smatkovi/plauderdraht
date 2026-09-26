import socket, ssl, select, sys, os, time, subprocess

LOCAL_PORT = 5223

def log(msg):
    t = time.strftime('%H:%M:%S')
    print("[%s] %s" % (t, msg), flush=True)

def get_xmpp_server():
    try:
        script = """
import dbus, sys
bus = dbus.SessionBus()
am = bus.get_object('org.freedesktop.Telepathy.AccountManager',
                    '/org/freedesktop/Telepathy/AccountManager')
props = dbus.Interface(am, 'org.freedesktop.DBus.Properties')
accounts = props.Get('org.freedesktop.Telepathy.AccountManager', 'ValidAccounts')
for a in accounts:
    path = str(a)
    if '/gabble/jabber/' in path:
        acct = bus.get_object('org.freedesktop.Telepathy.AccountManager', path)
        p = dbus.Interface(acct, 'org.freedesktop.DBus.Properties')
        params = p.Get('org.freedesktop.Telepathy.Account', 'Parameters')
        jid = str(params.get('account', ''))
        if '@' in jid:
            print(jid.split('@')[1])
            sys.exit(0)
sys.exit(1)
"""
        result = subprocess.run(
            ['/usr/bin/python', '-c', script],
            capture_output=True, text=True, timeout=10,
            env=dict(os.environ)
        )
        server = result.stdout.strip()
        if server:
            log("Found XMPP account -> server %s" % server)
            return server
    except Exception as e:
        log("D-Bus query failed: %s" % e)
    return None

def do_starttls(sock, server):
    sock.send(("<?xml version='1.0'?><stream:stream to='%s' xmlns='jabber:client' "
               "xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>" % server).encode())
    data = b''
    while b'</stream:features>' not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise Exception("Server closed during feature negotiation")
        data += chunk
        if len(data) > 65536:
            break
    if b'<starttls' not in data:
        raise Exception("Server does not support STARTTLS")
    log("Server features received")
    sock.send(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
    data = b''
    while b'<proceed' not in data and b'<failure' not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise Exception("Server closed during STARTTLS")
        data += chunk
    if b'<failure' in data:
        raise Exception("STARTTLS failed")
    log("Got proceed, upgrading to TLS...")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    tls_sock = ctx.wrap_socket(sock, server_hostname=server)
    log("TLS established: %s" % tls_sock.version())
    return tls_sock

def relay(client, server_tls):
    log("Relaying...")
    while True:
        try:
            r, _, x = select.select([client, server_tls], [], [client, server_tls], 300)
        except Exception as e:
            log("Select error: %s" % e)
            break
        if x:
            break
        if not r:
            try: client.sendall(b' ')
            except: break
            continue
        for s in r:
            try:
                data = s.recv(8192)
            except Exception as e:
                log("Recv error: %s" % e)
                return
            if not data:
                log("Connection closed")
                return
            try:
                if s is client:
                    server_tls.sendall(data)
                else:
                    client.sendall(data)
            except Exception as e:
                log("Send error: %s" % e)
                return

def main():
    server = get_xmpp_server()
    if not server:
        log("No XMPP account found, exiting")
        sys.exit(1)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', LOCAL_PORT))
    listener.listen(1)
    log("XMPP STARTTLS proxy for %s listening on localhost:%d" % (server, LOCAL_PORT))

    while True:
        client = None
        raw = None
        tls = None
        try:
            log("Waiting for connection...")
            client, addr = listener.accept()
            log("Client connected from %s" % (addr,))
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(15)
            raw.connect((server, 5222))
            log("Connected to %s:5222" % server)
            tls = do_starttls(raw, server)
            tls.settimeout(None)
            relay(client, tls)
        except Exception as e:
            log("Error: %s" % e)
        finally:
            for s in [tls, raw, client]:
                try:
                    if s: s.close()
                except: pass
            log("Session ended\n")

if __name__ == '__main__':
    main()
