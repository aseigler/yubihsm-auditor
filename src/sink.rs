//! Event destinations: stdout, JSON-lines file, Splunk HEC, or syslog.

use crate::{
    config::{Device, Output, SyslogFormat, SyslogProtocol},
    event::AuditEvent,
};
use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use std::{
    fs,
    io::{BufWriter, Write},
    net::{TcpStream, ToSocketAddrs, UdpSocket},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

/// A destination for transformed events.
///
/// `write` may buffer; nothing is considered durable until `flush` returns
/// `Ok`. The collector only advances the device log index after a successful
/// `flush`, so a failure here means the entries stay on the device.
pub trait Sink {
    fn write(&mut self, device: &Device, event: &AuditEvent) -> Result<()>;
    fn flush(&mut self) -> Result<()>;
}

pub fn build(output: &Output) -> Result<Box<dyn Sink>> {
    match output {
        Output::Stdout => Ok(Box::new(StdoutSink)),
        Output::File {
            path,
            rotate_bytes,
            rotate_keep,
        } => Ok(Box::new(FileSink::new(
            path.clone(),
            *rotate_bytes,
            *rotate_keep,
        )?)),
        Output::Hec { .. } => Ok(Box::new(HecSink::new(output)?)),
        Output::Syslog { .. } => Ok(Box::new(SyslogSink::new(output)?)),
    }
}

/// Splunk HEC envelope. The file and stdout sinks write the bare event
/// instead: a universal forwarder supplies host/source/sourcetype itself.
#[derive(Serialize)]
struct Envelope<'a> {
    time: f64,
    host: &'a str,
    source: &'a str,
    sourcetype: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    index: Option<&'a str>,
    event: &'a AuditEvent,
}

struct StdoutSink;

impl Sink for StdoutSink {
    fn write(&mut self, _device: &Device, event: &AuditEvent) -> Result<()> {
        let mut out = std::io::stdout().lock();
        serde_json::to_writer(&mut out, event)?;
        out.write_all(b"\n")?;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        std::io::stdout().lock().flush()?;
        Ok(())
    }
}

struct FileSink {
    path: PathBuf,
    rotate_bytes: u64,
    rotate_keep: u8,
    writer: BufWriter<fs::File>,
    written: u64,
}

impl FileSink {
    fn new(path: PathBuf, rotate_bytes: u64, rotate_keep: u8) -> Result<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            path,
            rotate_bytes,
            rotate_keep,
            writer: BufWriter::new(file),
            written,
        })
    }

    fn rotate_if_needed(&mut self) -> Result<()> {
        if self.rotate_bytes == 0 || self.written < self.rotate_bytes {
            return Ok(());
        }
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;

        for index in (1..=self.rotate_keep.max(1)).rev() {
            let src = if index == 1 {
                self.path.clone()
            } else {
                rolled_path(&self.path, index - 1)
            };
            let dst = rolled_path(&self.path, index);
            if src.exists() {
                if dst.exists() {
                    fs::remove_file(&dst).ok();
                }
                fs::rename(&src, &dst)
                    .with_context(|| format!("rotating {} -> {}", src.display(), dst.display()))?;
            }
        }

        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("reopening {}", self.path.display()))?;
        self.writer = BufWriter::new(file);
        self.written = 0;
        Ok(())
    }
}

fn rolled_path(path: &Path, index: u8) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{index}"));
    path.with_file_name(name)
}

impl Sink for FileSink {
    fn write(&mut self, _device: &Device, event: &AuditEvent) -> Result<()> {
        self.rotate_if_needed()?;
        let line = serde_json::to_vec(event)?;
        self.writer.write_all(&line)?;
        self.writer.write_all(b"\n")?;
        self.written += line.len() as u64 + 1;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        // fsync so an advanced log index can never outrun durable output.
        self.writer.get_ref().sync_all()?;
        Ok(())
    }
}

struct HecSink {
    agent: ureq::Agent,
    url: String,
    token: String,
    source: String,
    sourcetype: String,
    index: Option<String>,
    batch: Vec<u8>,
    pending: usize,
}

/// Splunk's default HEC payload limit is 800 KB; stay well under it.
const HEC_MAX_BATCH_BYTES: usize = 512 * 1024;

impl HecSink {
    fn new(output: &Output) -> Result<Self> {
        let Output::Hec {
            url,
            token,
            token_env,
            token_file,
            sourcetype,
            source,
            index,
            ca_cert_file,
            use_platform_roots,
            tls_insecure,
            timeout_ms,
        } = output
        else {
            bail!("not an HEC output");
        };

        let token = resolve_token(token.as_deref(), token_env.as_deref(), token_file.as_ref())?;

        let mut tls = ureq::tls::TlsConfig::builder();
        if *tls_insecure {
            tracing::warn!("HEC TLS certificate verification is disabled (tls_insecure = true)");
            tls = tls.disable_verification(true);
        } else if let Some(pem_path) = ca_cert_file {
            let pem = fs::read(pem_path)
                .with_context(|| format!("reading ca_cert_file {}", pem_path.display()))?;
            let certs: Vec<_> = ureq::tls::parse_pem(&pem)
                .filter_map(|item| match item {
                    Ok(ureq::tls::PemItem::Certificate(cert)) => Some(cert),
                    _ => None,
                })
                .collect();
            if certs.is_empty() {
                bail!("no certificates found in {}", pem_path.display());
            }
            tls = tls.root_certs(ureq::tls::RootCerts::new_with_certs(&certs));
        } else if *use_platform_roots {
            tls = tls.root_certs(ureq::tls::RootCerts::PlatformVerifier);
        }

        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_millis(*timeout_ms)))
            .tls_config(tls.build())
            .http_status_as_error(false)
            .build();

        Ok(Self {
            agent: ureq::Agent::new_with_config(config),
            url: format!("{}/services/collector/event", url.trim_end_matches('/')),
            token,
            source: source.clone(),
            sourcetype: sourcetype.clone(),
            index: index.clone(),
            batch: Vec::with_capacity(HEC_MAX_BATCH_BYTES),
            pending: 0,
        })
    }

    fn post_batch(&mut self) -> Result<()> {
        if self.batch.is_empty() {
            return Ok(());
        }
        let body = std::mem::take(&mut self.batch);
        let count = self.pending;
        self.pending = 0;

        let mut last_error = None;
        for attempt in 1..=4u32 {
            let response = self
                .agent
                .post(&self.url)
                .header("Authorization", &format!("Splunk {}", self.token))
                .header("Content-Type", "application/json")
                .send(&body[..]);

            match response {
                Ok(resp) if resp.status().is_success() => {
                    tracing::debug!(events = count, "delivered batch to HEC");
                    return Ok(());
                }
                Ok(mut resp) => {
                    let status = resp.status().as_u16();
                    let detail = resp
                        .body_mut()
                        .read_to_string()
                        .unwrap_or_else(|_| String::from("<unreadable body>"));
                    // 4xx other than 429 will not improve on retry.
                    if status != 429 && (400..500).contains(&status) {
                        return Err(anyhow!("HEC rejected batch: HTTP {status}: {detail}"));
                    }
                    last_error = Some(anyhow!("HEC returned HTTP {status}: {detail}"));
                }
                Err(e) => last_error = Some(anyhow!("HEC request failed: {e}")),
            }

            if attempt < 4 {
                let backoff = Duration::from_millis(500 * 2u64.pow(attempt - 1));
                tracing::warn!(attempt, ?backoff, "retrying HEC delivery");
                std::thread::sleep(backoff);
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("HEC delivery failed")))
    }
}

fn resolve_token(
    inline: Option<&str>,
    env_var: Option<&str>,
    file: Option<&PathBuf>,
) -> Result<String> {
    if let Some(var) = env_var {
        return std::env::var(var)
            .map_err(|_| anyhow!("environment variable {var} is not set (token_env)"));
    }
    if let Some(path) = file {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading token_file {}", path.display()))?;
        return Ok(raw.trim().to_owned());
    }
    inline
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("HEC output needs one of token_env, token_file, or token"))
}

impl Sink for HecSink {
    fn write(&mut self, device: &Device, event: &AuditEvent) -> Result<()> {
        let envelope = Envelope {
            time: event.time,
            host: &device.name,
            source: &self.source,
            sourcetype: &self.sourcetype,
            index: device.index.as_deref().or(self.index.as_deref()),
            event,
        };
        let json = serde_json::to_vec(&envelope)?;
        if !self.batch.is_empty() && self.batch.len() + json.len() > HEC_MAX_BATCH_BYTES {
            self.post_batch()?;
        }
        self.batch.extend_from_slice(&json);
        self.batch.push(b'\n');
        self.pending += 1;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.post_batch()
    }
}

/// A syslog transport. Only writing is needed; nothing here reads a response.
enum SyslogStream {
    Udp(UdpSocket),
    Tcp(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl SyslogStream {
    fn write_frame(&mut self, frame: &[u8]) -> std::io::Result<()> {
        match self {
            SyslogStream::Udp(socket) => socket.send(frame).map(|_| ()),
            SyslogStream::Tcp(stream) => stream.write_all(frame),
            SyslogStream::Tls(stream) => stream.write_all(frame),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            SyslogStream::Udp(_) => Ok(()),
            SyslogStream::Tcp(stream) => stream.flush(),
            SyslogStream::Tls(stream) => stream.flush(),
        }
    }
}

struct SyslogSink {
    protocol: SyslogProtocol,
    host: String,
    port: u16,
    connect_timeout: Duration,
    tls_config: Option<Arc<rustls::ClientConfig>>,
    octet_counting: bool,
    facility: u8,
    app_name: String,
    format: SyslogFormat,
    pid: u32,
    stream: SyslogStream,
}

impl SyslogSink {
    fn new(output: &Output) -> Result<Self> {
        let Output::Syslog {
            protocol,
            host,
            port,
            tls,
            ca_cert_file,
            use_platform_roots,
            tls_insecure,
            octet_counting,
            facility,
            app_name,
            format,
            timeout_ms,
        } = output
        else {
            bail!("not a syslog output");
        };

        let connect_timeout = Duration::from_millis(*timeout_ms);
        let tls_config = if *tls {
            Some(build_syslog_tls_config(
                ca_cert_file.as_ref(),
                *use_platform_roots,
                *tls_insecure,
            )?)
        } else {
            None
        };

        let stream = connect_syslog(
            *protocol,
            host,
            *port,
            connect_timeout,
            tls_config.as_ref(),
        )?;

        Ok(Self {
            protocol: *protocol,
            host: host.clone(),
            port: *port,
            connect_timeout,
            tls_config,
            octet_counting: *octet_counting,
            facility: *facility,
            app_name: app_name.clone(),
            format: *format,
            pid: std::process::id(),
            stream,
        })
    }

    fn reconnect(&mut self) -> Result<()> {
        self.stream = connect_syslog(
            self.protocol,
            &self.host,
            self.port,
            self.connect_timeout,
            self.tls_config.as_ref(),
        )?;
        Ok(())
    }

    /// RFC 5424 header, with MSG shaped by `self.format`. No STRUCTURED-DATA:
    /// the `json` format carries everything in MSG for a generic receiver
    /// (Wazuh, rsyslog, syslog-ng, ...); the `cef` format instead uses ArcSight
    /// Common Event Format there, for SIEMs that parse CEF natively.
    fn format_message(&self, device: &Device, event: &AuditEvent) -> Result<Vec<u8>> {
        let severity = syslog_severity(event);
        let pri = self.facility * 8 + severity;
        let timestamp = crate::event::iso8601(event.time);
        let hostname = sanitize_syslog_field(&device.name);
        let app_name = sanitize_syslog_field(&self.app_name);
        let msgid = sanitize_syslog_field(event.event_type);

        let msg = match self.format {
            SyslogFormat::Json => serde_json::to_string(event)?,
            SyslogFormat::Cef => format_cef(event)?,
        };

        let mut out = Vec::with_capacity(msg.len() + 64);
        write!(
            out,
            "<{pri}>1 {timestamp} {hostname} {app_name} {pid} {msgid} - {msg}",
            pid = self.pid,
        )?;
        Ok(out)
    }
}

/// ArcSight Common Event Format: `CEF:0|Vendor|Product|Version|SigID|Name|Sev|Ext`.
/// Standard extension keys (`act`, `outcome`, `cat`, `rt`, ...) map the fields a
/// generic CEF consumer already knows how to display; everything else rides in
/// the numbered `cs`/`cn` slots (labelled) plus a `msg` extension carrying the
/// full event as JSON, so nothing is lost for a receiver that only understands
/// the standard keys.
fn format_cef(event: &AuditEvent) -> Result<String> {
    let severity = cef_severity(event);
    let signature_id = event
        .command_code
        .map(|c| c.to_string())
        .unwrap_or_else(|| event.event_type.to_owned());
    let name = event.command.as_deref().unwrap_or(event.event_type);
    let device_version = event.device_version.as_deref().unwrap_or("unknown");

    let mut ext = String::new();
    let mut push = |key: &str, value: &str| {
        if !ext.is_empty() {
            ext.push(' ');
        }
        ext.push_str(key);
        ext.push('=');
        ext.push_str(&cef_escape_extension(value));
    };

    push("rt", &((event.time * 1000.0).round() as i64).to_string());
    push("dvchost", &event.device_name);
    if let Some(serial) = &event.device_serial {
        push("deviceExternalId", serial);
    }
    if let Some(category) = event.command_category {
        push("cat", category);
    }
    if let Some(command) = &event.command {
        push("act", command);
    }
    if let Some(result) = event.result {
        push("outcome", result);
    }
    if let Some(v) = &event.session_key_id_hex {
        push("cs1Label", "SessionKeyId");
        push("cs1", v);
    }
    if let Some(v) = &event.target_key_id_hex {
        push("cs2Label", "TargetKeyId");
        push("cs2", v);
    }
    if let Some(v) = &event.second_key_id_hex {
        push("cs3Label", "SecondKeyId");
        push("cs3", v);
    }
    if let Some(v) = event.chain_status {
        push("cs4Label", "ChainStatus");
        push("cs4", v);
    }
    if let Some(v) = &event.log_digest {
        push("cs5Label", "LogDigest");
        push("cs5", v);
    }
    push("cs6Label", "DeviceInfoSource");
    push("cs6", event.device_info_source);
    push("cn1Label", "Sequence");
    push("cn1", &event.sequence.to_string());
    if let Some(v) = event.log_store_percent_used {
        push("cn2Label", "LogStorePercentUsed");
        push("cn2", &v.to_string());
    }
    push("cn3Label", "BootSession");
    push("cn3", &event.boot_session.to_string());
    let json = serde_json::to_string(event)?;
    push("msg", &json);

    Ok(format!(
        "CEF:0|Yubico|YubiHSM2|{version}|{sig}|{name}|{severity}|{ext}",
        version = cef_escape_header(device_version),
        sig = cef_escape_header(&signature_id),
        name = cef_escape_header(name),
    ))
}

/// CEF severity is 0-10, higher is more severe (the opposite direction from
/// syslog severity), so this is a separate mapping from `syslog_severity`.
fn cef_severity(event: &AuditEvent) -> u8 {
    match event.event_type {
        "unlogged_events" => 9,
        "command" if event.chain_status == Some("mismatch") => 9,
        "command" if event.result == Some("error") => 6,
        "command" if event.key_management == Some(true) => 5,
        _ => 3,
    }
}

/// CEF header fields (Vendor/Product/Version/Signature/Name) may not contain
/// unescaped `|` or `\`.
fn cef_escape_header(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace(['\n', '\r'], " ")
}

/// CEF extension values may not contain unescaped `=` or `\`, and must be a
/// single line.
fn cef_escape_extension(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace(['\n', '\r'], " ")
}

fn syslog_severity(event: &AuditEvent) -> u8 {
    match event.event_type {
        "unlogged_events" => 2, // critical: an audit gap
        "command" if event.chain_status == Some("mismatch") => 2,
        "command" if event.result == Some("error") => 4, // warning
        "command" if event.key_management == Some(true) => 5, // notice
        _ => 6, // informational
    }
}

/// syslog HEADER fields (HOSTNAME/APP-NAME/MSGID) must be printable ASCII with
/// no spaces; fall back to `-` (NILVALUE) rather than emit a malformed frame.
fn sanitize_syslog_field(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|c| if c.is_ascii_graphic() { c } else { '_' })
        .collect();
    if cleaned.is_empty() {
        "-".to_owned()
    } else {
        cleaned
    }
}

fn connect_syslog(
    protocol: SyslogProtocol,
    host: &str,
    port: u16,
    timeout: Duration,
    tls_config: Option<&Arc<rustls::ClientConfig>>,
) -> Result<SyslogStream> {
    let addr = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {host}:{port}"))?
        .next()
        .ok_or_else(|| anyhow!("no addresses for {host}:{port}"))?;

    match protocol {
        SyslogProtocol::Udp => {
            let bind_addr = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
            let socket = UdpSocket::bind(bind_addr).context("binding UDP socket")?;
            socket
                .connect(addr)
                .with_context(|| format!("connecting UDP socket to {addr}"))?;
            Ok(SyslogStream::Udp(socket))
        }
        SyslogProtocol::Tcp => {
            let tcp = TcpStream::connect_timeout(&addr, timeout)
                .with_context(|| format!("connecting to {addr}"))?;
            tcp.set_nodelay(true).ok();
            tcp.set_write_timeout(Some(timeout)).ok();

            match tls_config {
                Some(config) => {
                    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
                        .with_context(|| format!("{host} is not a valid TLS server name"))?;
                    let conn = rustls::ClientConnection::new(config.clone(), server_name)
                        .context("initialising TLS session")?;
                    Ok(SyslogStream::Tls(Box::new(rustls::StreamOwned::new(
                        conn, tcp,
                    ))))
                }
                None => Ok(SyslogStream::Tcp(tcp)),
            }
        }
    }
}

/// Verifier that accepts any server certificate. Only used when
/// `tls_insecure = true`, which is documented as lab-only.
#[derive(Debug)]
struct NoServerCertVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for NoServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn build_syslog_tls_config(
    ca_cert_file: Option<&PathBuf>,
    use_platform_roots: bool,
    tls_insecure: bool,
) -> Result<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("configuring TLS protocol versions")?;

    let config = if tls_insecure {
        tracing::warn!("syslog TLS certificate verification is disabled (tls_insecure = true)");
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoServerCertVerifier { provider }))
            .with_no_client_auth()
    } else if let Some(path) = ca_cert_file {
        let pem =
            fs::read(path).with_context(|| format!("reading ca_cert_file {}", path.display()))?;
        let certs: Vec<_> = rustls_pemfile::certs(&mut &pem[..])
            .collect::<std::result::Result<_, _>>()
            .with_context(|| format!("parsing ca_cert_file {}", path.display()))?;
        let mut root_store = rustls::RootCertStore::empty();
        let (added, _ignored) = root_store.add_parsable_certificates(certs);
        if added == 0 {
            bail!("no usable certificates found in {}", path.display());
        }
        builder
            .with_root_certificates(root_store)
            .with_no_client_auth()
    } else if use_platform_roots {
        use rustls_platform_verifier::BuilderVerifierExt;
        builder
            .with_platform_verifier()
            .context("configuring platform certificate verifier")?
            .with_no_client_auth()
    } else {
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };
    Ok(Arc::new(config))
}

impl Sink for SyslogSink {
    fn write(&mut self, device: &Device, event: &AuditEvent) -> Result<()> {
        let message = self.format_message(device, event)?;

        let frame: Vec<u8> = match (self.protocol, self.octet_counting) {
            (SyslogProtocol::Tcp, true) => {
                let mut framed = format!("{} ", message.len()).into_bytes();
                framed.extend_from_slice(&message);
                framed
            }
            (SyslogProtocol::Tcp, false) => {
                let mut framed = message;
                framed.push(b'\n');
                framed
            }
            (SyslogProtocol::Udp, _) => message,
        };

        // One reconnect attempt: TCP connections idle out or get reset by
        // middleboxes between polls, and a fresh connection is cheap.
        if let Err(e) = self.stream.write_frame(&frame) {
            if self.protocol == SyslogProtocol::Udp {
                return Err(e).context("sending syslog datagram");
            }
            tracing::warn!(error = %e, "syslog connection dropped; reconnecting");
            self.reconnect().context("reconnecting to syslog receiver")?;
            self.stream
                .write_frame(&frame)
                .context("sending syslog message after reconnect")?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.stream.flush().context("flushing syslog connection")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cef_extension_escaping() {
        assert_eq!(cef_escape_extension("a=b"), "a\\=b");
        assert_eq!(cef_escape_extension("a\\b"), "a\\\\b");
        assert_eq!(cef_escape_extension("a\nb"), "a b");
    }

    #[test]
    fn cef_header_escaping() {
        assert_eq!(cef_escape_header("a|b"), "a\\|b");
        assert_eq!(cef_escape_header("a\\b"), "a\\\\b");
    }

    #[test]
    fn cef_message_has_expected_shape() {
        let ctx = crate::event::PollContext {
            device_name: "hsm-1".into(),
            connector_url: "http://10.0.0.1:12345".into(),
            device_info_source: "session",
            device_serial: Some("0000001234".into()),
            device_version: Some("2.4.0".into()),
            log_store_used: Some(31),
            log_store_capacity: Some(62),
            observed_at_epoch: 1_700_000_000.0,
            tick_hz: 1.0,
            tags: std::collections::BTreeMap::new(),
        };
        let entry = crate::event::LogEntry {
            item: 9,
            cmd: yubihsm::command::Code::SignEcdsa,
            length: 32,
            session_key: 4,
            target_key: 0x100,
            second_key: crate::codes::NO_KEY,
            result: yubihsm::response::Code::Success(yubihsm::command::Code::SignEcdsa),
            tick: 500,
            digest: [0u8; 16],
        };
        let event = ctx.entry_event(
            &entry,
            42,
            3,
            Some("ok"),
            crate::event::TimeEstimate {
                epoch: 1_699_999_990.0,
                source: "tick_anchor",
                uncertainty_secs: 60.0,
            },
        );
        let cef = format_cef(&event).unwrap();
        assert!(cef.starts_with("CEF:0|Yubico|YubiHSM2|2.4.0|86|sign_ecdsa|"));
        assert!(cef.contains("outcome=success"));
        assert!(cef.contains("cs1=0x0004"));
        assert!(cef.contains("msg={"));
    }

    #[test]
    fn syslog_field_sanitization() {
        assert_eq!(sanitize_syslog_field("hsm-iad1-01"), "hsm-iad1-01");
        assert_eq!(sanitize_syslog_field("has space"), "has_space");
        assert_eq!(sanitize_syslog_field(""), "-");
    }

    #[test]
    fn rolled_paths_are_numbered() {
        let path = PathBuf::from("/var/log/audit.jsonl");
        assert_eq!(
            rolled_path(&path, 3),
            PathBuf::from("/var/log/audit.jsonl.3")
        );
    }

    #[test]
    fn token_from_inline_file_and_errors() {
        assert_eq!(resolve_token(Some("inline"), None, None).unwrap(), "inline");
        assert!(resolve_token(None, None, None).is_err());
        assert!(resolve_token(None, Some("YHA_TEST_MISSING_VAR"), None).is_err());

        let path = std::env::temp_dir().join(format!("yha-token-{}.txt", std::process::id()));
        fs::write(
            &path,
            "from-file
",
        )
        .unwrap();
        // A file wins over an inline token, and trailing newlines are trimmed.
        assert_eq!(
            resolve_token(Some("inline"), None, Some(&path)).unwrap(),
            "from-file"
        );
        fs::remove_file(&path).ok();
    }
}
