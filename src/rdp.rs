//! RDP session worker.
//!
//! MeatShell does not embed a full RDP renderer. Instead it starts a short-lived
//! loopback TCP tunnel and launches the platform RDP client with a temporary
//! `.rdp` file that points at that local port. The tunnel then connects to the
//! real target directly, or through the same SOCKS5 / HTTP proxy plumbing used
//! by SSH and Telnet.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;

use crate::config::Session;
use crate::i18n::t;
use crate::proxy::ProxyConfig;
use crate::ssh::{SessionCommand, SessionEvent, SessionHandle};

const DEFAULT_RDP_PORT: u16 = 3389;

pub fn spawn_rdp_session(
    runtime: &tokio::runtime::Handle,
    tab_id: String,
    session: Session,
) -> (SessionHandle, UnboundedReceiver<SessionEvent>) {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<SessionCommand>();
    let (evt_tx, evt_rx) = mpsc::unbounded_channel::<SessionEvent>();

    let evt_for_task = evt_tx.clone();
    let join = runtime.spawn(async move {
        if let Err(err) = run_rdp(session, cmd_rx, evt_for_task.clone()).await {
            let _ = evt_for_task.send(SessionEvent::Closed(format!("{err:#}")));
        }
    });

    (
        SessionHandle {
            tab_id,
            commands: cmd_tx,
            join,
        },
        evt_rx,
    )
}

async fn run_rdp(
    session: Session,
    mut commands: UnboundedReceiver<SessionCommand>,
    events: UnboundedSender<SessionEvent>,
) -> Result<()> {
    let host = session.host.trim().to_string();
    if host.is_empty() {
        bail!("{}", t("RDP 主机为空", "RDP host is empty"));
    }
    let port = if session.port == 0 {
        DEFAULT_RDP_PORT
    } else {
        session.port
    };
    let target = format!("{host}:{port}");

    let proxy = crate::proxy::resolve(&session.proxy);
    let route = match &proxy {
        Some(p) => format!("{} {}", t("代理", "proxy"), crate::proxy::describe(p)),
        None => t("直连", "direct").to_string(),
    };

    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("bind RDP loopback tunnel")?;
    let local_addr = listener
        .local_addr()
        .context("read RDP loopback tunnel address")?;
    let rdp_file = write_rdp_file(&session, local_addr.port())?;

    let _ = events.send(SessionEvent::Status(format!(
        "{} {} → {}",
        t("RDP 隧道就绪", "RDP tunnel ready"),
        local_addr,
        target
    )));

    if let Err(err) = open_rdp_client(&rdp_file, local_addr.port(), &session.user) {
        let _ = fs::remove_file(&rdp_file);
        return Err(err).with_context(|| {
            t(
                "启动系统 RDP 客户端失败",
                "failed to launch system RDP client",
            )
        });
    }

    let _ = events.send(SessionEvent::Connected);
    let _ = events.send(SessionEvent::Output(format!(
        "\r\n{}\r\n{}: {}\r\n{}: {}\r\n{}: {}\r\n\r\n",
        t(
            "已打开系统 RDP 客户端。RDP 画面在外部窗口中显示，关闭此标签会停止本地隧道。",
            "Opened the system RDP client. The desktop is shown in the external window; closing this tab stops the local tunnel."
        ),
        t("目标", "Target"),
        target,
        t("路由", "Route"),
        route,
        t("本地端口", "Local endpoint"),
        local_addr
    )));

    let mut relays: Vec<JoinHandle<()>> = Vec::new();
    loop {
        relays.retain(|h| !h.is_finished());
        tokio::select! {
            cmd = commands.recv() => {
                match cmd {
                    Some(SessionCommand::Close) | None => break,
                    Some(SessionCommand::RawInput(_)) => {
                        let _ = events.send(SessionEvent::Status(t(
                            "RDP 会话在外部窗口中运行",
                            "RDP session is running in the external window"
                        ).into()));
                    }
                    Some(SessionCommand::Resize(_, _)) => {}
                }
            }
            accepted = listener.accept() => {
                let (client, peer) = accepted.context("accept RDP loopback connection")?;
                let target_host = host.clone();
                let proxy_cfg = proxy.clone();
                let events_for_relay = events.clone();
                let target_for_msg = target.clone();
                relays.push(tokio::spawn(async move {
                    let _ = events_for_relay.send(SessionEvent::Status(format!(
                        "{} {} → {}",
                        t("RDP 客户端已连接", "RDP client connected"),
                        peer,
                        target_for_msg
                    )));
                    if let Err(err) = relay_rdp(client, proxy_cfg, target_host, port).await {
                        let _ = events_for_relay.send(SessionEvent::Status(format!(
                            "{}: {err:#}",
                            t("RDP 隧道错误", "RDP tunnel error")
                        )));
                    }
                }));
            }
        }
    }

    for relay in relays {
        relay.abort();
    }
    let _ = fs::remove_file(&rdp_file);
    let _ = events.send(SessionEvent::Closed(
        t("RDP 隧道已关闭", "RDP tunnel closed").into(),
    ));
    Ok(())
}

async fn relay_rdp(
    mut client: TcpStream,
    proxy: Option<ProxyConfig>,
    target_host: String,
    target_port: u16,
) -> Result<()> {
    let _ = client.set_nodelay(true);
    let mut remote = match proxy {
        Some(p) => crate::proxy::connect(&p, &target_host, target_port)
            .await
            .with_context(|| format!("proxy connect to {target_host}:{target_port} failed"))?,
        None => TcpStream::connect((target_host.as_str(), target_port))
            .await
            .with_context(|| format!("connect {target_host}:{target_port} failed"))?,
    };
    let _ = remote.set_nodelay(true);
    let _ = copy_bidirectional(&mut client, &mut remote)
        .await
        .context("RDP relay failed")?;
    Ok(())
}

fn write_rdp_file(session: &Session, local_port: u16) -> Result<PathBuf> {
    let path = std::env::temp_dir().join(format!("meatshell-rdp-{}.rdp", uuid::Uuid::new_v4()));
    let body = rdp_file_body(session, local_port);
    fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

fn rdp_file_body(session: &Session, local_port: u16) -> String {
    let username = clean_rdp_value(&session.user);
    let mut lines = vec![
        "screen mode id:i:2".to_string(),
        "use multimon:i:0".to_string(),
        "desktopwidth:i:1440".to_string(),
        "desktopheight:i:900".to_string(),
        "session bpp:i:32".to_string(),
        format!("full address:s:127.0.0.1:{local_port}"),
        "prompt for credentials:i:1".to_string(),
        "promptcredentialonce:i:0".to_string(),
        "authentication level:i:2".to_string(),
        "redirectclipboard:i:1".to_string(),
        "redirectprinters:i:0".to_string(),
        "redirectsmartcards:i:0".to_string(),
        "audiomode:i:0".to_string(),
    ];
    if !username.is_empty() {
        lines.push(format!("username:s:{username}"));
    }
    lines.push(String::new());
    lines.join("\r\n")
}

fn clean_rdp_value(value: &str) -> String {
    value
        .chars()
        .filter(|c| *c != '\r' && *c != '\n')
        .collect::<String>()
}

#[cfg(target_os = "macos")]
fn open_rdp_client(path: &Path, _local_port: u16, _user: &str) -> Result<()> {
    Command::new("open")
        .arg(path)
        .spawn()
        .with_context(|| format!("open {}", path.display()))?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn open_rdp_client(path: &Path, _local_port: u16, _user: &str) -> Result<()> {
    Command::new("mstsc")
        .arg(path)
        .spawn()
        .with_context(|| format!("mstsc {}", path.display()))?;
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn open_rdp_client(path: &Path, local_port: u16, user: &str) -> Result<()> {
    let mut args = vec![
        format!("/v:127.0.0.1:{local_port}"),
        "/dynamic-resolution".to_string(),
        "/clipboard".to_string(),
    ];
    let user = clean_rdp_value(user);
    if !user.is_empty() {
        args.push(format!("/u:{user}"));
    }
    for program in ["xfreerdp", "wlfreerdp"] {
        match Command::new(program).args(&args).spawn() {
            Ok(_) => return Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err).with_context(|| format!("launch {program}")),
        }
    }
    Command::new("xdg-open")
        .arg(path)
        .spawn()
        .with_context(|| format!("xdg-open {}", path.display()))?;
    Ok(())
}

#[cfg(not(any(unix, target_os = "windows")))]
fn open_rdp_client(_path: &Path, _local_port: u16, _user: &str) -> Result<()> {
    bail!("no RDP launcher is available on this platform");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Secret;

    #[test]
    fn rdp_file_points_to_loopback_and_omits_password() {
        let mut session = Session::new_empty();
        session.kind = crate::config::SessionKind::Rdp;
        session.host = "10.0.0.7".into();
        session.port = DEFAULT_RDP_PORT;
        session.user = "admin".into();
        session.password = Secret::new("do-not-write");

        let body = rdp_file_body(&session, 49152);
        assert!(body.contains("full address:s:127.0.0.1:49152"));
        assert!(body.contains("username:s:admin"));
        assert!(!body.contains("10.0.0.7"));
        assert!(!body.contains("do-not-write"));
    }

    #[test]
    fn rdp_values_strip_line_breaks() {
        assert_eq!(clean_rdp_value("domain\\user\r\nx"), "domain\\userx");
    }
}
