//! Plauderdraht -- STARTTLS fuer Harmattans XMPP-Konto.
//!
//! Nachbau von `xmpp-proxy.py` in Rust. Warum es das Programm gibt:
//! Harmattans gabble bringt einen OpenSSL-Stand von 2011 mit und kommt an
//! keinen Server mehr heran, der TLS 1.2 verlangt. Das Konto ist deshalb
//! auf `localhost:5223` gestellt, und hier davor sitzt dieser Draht: er
//! nimmt die Verbindung im Klartext an, baut selbst eine zum echten Server
//! auf, handelt dort STARTTLS aus und reicht danach nur noch Bytes durch.
//!
//! Gegenueber der Python-Fassung aendert sich nichts an der Mechanik --
//! dieselben Bytemuster, dieselbe Reihenfolge, dieselbe Leerzeichen-
//! Lebenszeichen alle 300 s. Nur der Arbeitsspeicher: rund 0,9 MB werden
//! zu etwa 0,2 MB.
//!
//! **Nicht geprueft wird das Serverzertifikat**, genau wie vorher
//! (`CERT_NONE`). Das ist hier vertretbar und anderswo nicht: der Draht
//! laeuft auf demselben Geraet wie der Klient, und die Alternative waere
//! kein TLS, sondern gar keine Verbindung -- die alte Wurzelliste des
//! Geraets kennt die heutigen Aussteller nicht.

// Siehe ohrwacht: die Aliasse muessen zu `libc::timeval` passen, und die
// aendern sich mit ihnen zusammen.
#![allow(deprecated)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::{AsRawFd, RawFd};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};

const LAUSCHPORT: u16 = 5223;
const XMPP_PORT: u16 = 5222;
const LEBENSZEICHEN: Duration = Duration::from_secs(300);
const VERBINDUNGSFRIST: Duration = Duration::from_secs(15);

fn notiz(text: &str) {
    // Die Uhrzeit kommt von der libc, damit keine Zeitzonenkiste noetig ist.
    let mut jetzt = unsafe { libc::time(std::ptr::null_mut()) };
    let mut teile: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&mut jetzt, &mut teile) };
    println!(
        "[{:02}:{:02}:{:02}] {}",
        teile.tm_hour, teile.tm_min, teile.tm_sec, text
    );
    let _ = std::io::stdout().flush();
}

// --- Welcher Server? -----------------------------------------------------

/// Die Domain des eingerichteten Jabber-Kontos, oder nichts.
///
/// Gefragt wird `mc-tool`, weil die Konten je nach Geraet im rtcom-Keyfile
/// **oder** in libaccounts stehen und nur Mission Control beides kennt. Aus
/// seiner Ausgabe wird ausschliesslich die Zeile `Normalized:` gelesen --
/// in derselben Ausgabe steht auch das Passwort, und das hat hier nichts
/// zu suchen.
fn server_aus_konto() -> Option<String> {
    let liste = Command::new("mc-tool").arg("list").output().ok()?;
    let konten = String::from_utf8_lossy(&liste.stdout);
    for konto in konten.lines() {
        if !konto.contains("/gabble/jabber/") && !konto.starts_with("gabble/jabber/") {
            continue;
        }
        let Ok(zeigen) = Command::new("mc-tool").args(["show", konto.trim()]).output() else {
            continue;
        };
        for zeile in String::from_utf8_lossy(&zeigen.stdout).lines() {
            let Some(rest) = zeile.trim().strip_prefix("Normalized:") else {
                continue;
            };
            if let Some((_, domain)) = rest.trim().split_once('@') {
                if !domain.is_empty() {
                    return Some(domain.to_string());
                }
            }
        }
    }
    None
}

// --- TLS -----------------------------------------------------------------

/// Nimmt jedes Zertifikat an. Siehe die Begruendung im Kopf der Datei.
#[derive(Debug)]
struct NimmtJedes;

impl ServerCertVerifier for NimmtJedes {
    fn verify_server_cert(
        &self,
        _end: &CertificateDer<'_>,
        _zwischen: &[CertificateDer<'_>],
        _name: &ServerName<'_>,
        _ocsp: &[u8],
        _jetzt: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _nachricht: &[u8],
        _zertifikat: &CertificateDer<'_>,
        _unterschrift: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _nachricht: &[u8],
        _zertifikat: &CertificateDer<'_>,
        _unterschrift: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// Liest, bis eines der Muster im Strom steht. Kein XML-Zerleger: der
/// Stromkopf ist noch gar kein vollstaendiges Dokument, und die
/// Python-Fassung suchte aus demselben Grund nach Bytes.
fn lesen_bis(strom: &mut TcpStream, muster: &[&[u8]], grenze: usize) -> std::io::Result<Vec<u8>> {
    let mut gesammelt = Vec::new();
    let mut brocken = [0u8; 4096];
    loop {
        let gelesen = strom.read(&mut brocken)?;
        if gelesen == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Server hat die Verbindung geschlossen",
            ));
        }
        gesammelt.extend_from_slice(&brocken[..gelesen]);
        if muster.iter().any(|m| enthaelt(&gesammelt, m)) {
            return Ok(gesammelt);
        }
        if gesammelt.len() > grenze {
            return Ok(gesammelt);
        }
    }
}

fn enthaelt(heuhaufen: &[u8], nadel: &[u8]) -> bool {
    heuhaufen.windows(nadel.len()).any(|f| f == nadel)
}

fn starttls(
    mut roh: TcpStream,
    server: &str,
    einstellungen: Arc<ClientConfig>,
) -> Result<StreamOwned<ClientConnection, TcpStream>, String> {
    let kopf = format!(
        "<?xml version='1.0'?><stream:stream to='{}' xmlns='jabber:client' \
         xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>",
        server
    );
    roh.write_all(kopf.as_bytes()).map_err(|e| e.to_string())?;

    let merkmale = lesen_bis(&mut roh, &[b"</stream:features>"], 65536).map_err(|e| e.to_string())?;
    if !enthaelt(&merkmale, b"<starttls") {
        return Err("Server kann kein STARTTLS".into());
    }
    notiz("Merkmale des Servers gelesen");

    roh.write_all(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        .map_err(|e| e.to_string())?;
    let antwort = lesen_bis(&mut roh, &[b"<proceed", b"<failure"], 65536).map_err(|e| e.to_string())?;
    if enthaelt(&antwort, b"<failure") {
        return Err("STARTTLS abgelehnt".into());
    }
    notiz("proceed bekommen, schalte auf TLS um");

    let name = ServerName::try_from(server.to_string()).map_err(|e| e.to_string())?;
    let verbindung = ClientConnection::new(einstellungen, name).map_err(|e| e.to_string())?;
    let mut strom = StreamOwned::new(verbindung, roh);
    // Den Handschlag jetzt abschliessen, damit ein Fehler hier auffaellt
    // und nicht erst beim ersten Byte des Klienten.
    strom.conn.complete_io(&mut strom.sock).map_err(|e| e.to_string())?;
    let fassung = strom
        .conn
        .protocol_version()
        .map(|v| format!("{:?}", v))
        .unwrap_or_else(|| "?".into());
    notiz(&format!("TLS steht: {}", fassung));
    Ok(strom)
}

// --- Durchreichen --------------------------------------------------------

fn lesbar(erste: RawFd, zweite: RawFd, frist: Duration) -> (bool, bool, bool) {
    let mut menge: libc::fd_set = unsafe { std::mem::zeroed() };
    unsafe {
        libc::FD_ZERO(&mut menge);
        libc::FD_SET(erste, &mut menge);
        libc::FD_SET(zweite, &mut menge);
    }
    let mut zeit = libc::timeval {
        tv_sec: frist.as_secs() as libc::time_t,
        tv_usec: frist.subsec_micros() as libc::suseconds_t,
    };
    let hoechste = erste.max(zweite);
    let bereit = unsafe {
        libc::select(
            hoechste + 1,
            &mut menge,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut zeit,
        )
    };
    if bereit < 0 {
        return (false, false, true);
    }
    (
        unsafe { libc::FD_ISSET(erste, &menge) },
        unsafe { libc::FD_ISSET(zweite, &menge) },
        false,
    )
}

fn durchreichen(klient: &mut TcpStream, server: &mut StreamOwned<ClientConnection, TcpStream>) {
    notiz("reiche durch");
    let klient_fd = klient.as_raw_fd();
    let server_fd = server.sock.as_raw_fd();
    let mut puffer = [0u8; 8192];
    loop {
        let (vom_klienten, vom_server, fehler) = lesbar(klient_fd, server_fd, LEBENSZEICHEN);
        if fehler {
            return;
        }
        if !vom_klienten && !vom_server {
            // Nichts passiert: ein Leerzeichen haelt die Leitung offen,
            // so wie es XMPP selbst tut.
            if klient.write_all(b" ").is_err() {
                return;
            }
            continue;
        }
        if vom_klienten {
            match klient.read(&mut puffer) {
                Ok(0) | Err(_) => {
                    notiz("Klient hat aufgelegt");
                    return;
                }
                Ok(n) => {
                    if server.write_all(&puffer[..n]).is_err() || server.flush().is_err() {
                        return;
                    }
                }
            }
        }
        if vom_server {
            match server.read(&mut puffer) {
                Ok(0) | Err(_) => {
                    notiz("Server hat aufgelegt");
                    return;
                }
                Ok(n) => {
                    if klient.write_all(&puffer[..n]).is_err() {
                        return;
                    }
                }
            }
        }
    }
}

// --- main ----------------------------------------------------------------

/// Sitzungsbus und HOME nachtragen, wenn sie fehlen.
///
/// Der Upstart-Job unter `/etc/init/apps` laeuft als nackter root ohne
/// Sitzung, `mc-tool` braucht aber beides. Harmattan schreibt die Adresse
/// des Busses in diese Datei, und die ist die aktuelle -- das Absuchen von
/// `/proc` liefert gern eine Leiche aus einer frueheren Sitzung.
fn sitzung_nachtragen() {
    if std::env::var_os("HOME").is_none() {
        std::env::set_var("HOME", "/home/user");
    }
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some() {
        return;
    }
    let Ok(inhalt) = std::fs::read_to_string("/tmp/session_bus_address.user") else {
        return;
    };
    for zeile in inhalt.lines() {
        let Some((_, wert)) = zeile.split_once("DBUS_SESSION_BUS_ADDRESS=") else {
            continue;
        };
        let wert = wert.trim().trim_end_matches(';').trim_matches('"').trim_matches('\'');
        if !wert.is_empty() {
            std::env::set_var("DBUS_SESSION_BUS_ADDRESS", wert);
            return;
        }
    }
}

fn main() {
    sitzung_nachtragen();
    let server = match std::env::args().nth(1) {
        Some(s) => s,
        None => match server_aus_konto() {
            Some(s) => {
                notiz(&format!("Jabber-Konto gefunden -> Server {}", s));
                s
            }
            None => {
                notiz("kein Jabber-Konto gefunden, Ende");
                std::process::exit(1);
            }
        },
    };

    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        notiz("Kryptoanbieter liess sich nicht setzen");
        std::process::exit(1);
    }
    let einstellungen = Arc::new(
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NimmtJedes))
            .with_no_client_auth(),
    );

    let horcher = match TcpListener::bind(("127.0.0.1", LAUSCHPORT)) {
        Ok(h) => h,
        Err(e) => {
            notiz(&format!("Port {} liess sich nicht belegen: {}", LAUSCHPORT, e));
            std::process::exit(1);
        }
    };
    notiz(&format!(
        "STARTTLS-Draht fuer {} horcht auf localhost:{}",
        server, LAUSCHPORT
    ));

    // Eine Sitzung nach der anderen, wie vorher: gabble haelt genau eine.
    loop {
        notiz("warte auf eine Verbindung");
        let Ok((mut klient, von)) = horcher.accept() else {
            continue;
        };
        notiz(&format!("Klient von {}", von));

        let ziel = match std::net::ToSocketAddrs::to_socket_addrs(&(server.as_str(), XMPP_PORT)) {
            Ok(mut a) => a.next(),
            Err(e) => {
                notiz(&format!("{} laesst sich nicht aufloesen: {}", server, e));
                None
            }
        };
        if let Some(ziel) = ziel {
            match TcpStream::connect_timeout(&ziel, VERBINDUNGSFRIST) {
                Ok(roh) => {
                    notiz(&format!("verbunden mit {}:{}", server, XMPP_PORT));
                    match starttls(roh, &server, einstellungen.clone()) {
                        Ok(mut tls) => durchreichen(&mut klient, &mut tls),
                        Err(e) => notiz(&format!("STARTTLS gescheitert: {}", e)),
                    }
                }
                Err(e) => notiz(&format!("keine Verbindung zu {}: {}", server, e)),
            }
        }
        let _ = klient.shutdown(std::net::Shutdown::Both);
        notiz("Sitzung beendet\n");
    }
}
