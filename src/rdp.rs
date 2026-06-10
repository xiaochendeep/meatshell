//! In-app RDP session worker.
//!
//! This module uses the pure-Rust `rdp-rs` protocol stack directly. No platform
//! RDP client is launched: the worker performs the RDP handshake, decodes bitmap
//! updates into an RGBA framebuffer, and sends keyboard/mouse input back to the
//! remote session.

use std::io;
use std::net::TcpStream as StdTcpStream;
#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rdp::core::client::Connector;
use rdp::core::event::{BitmapEvent, KeyboardEvent, PointerButton, PointerEvent, RdpEvent};
use rdp::model::error::{Error as RdpError, RdpErrorKind};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::Session;
use crate::i18n::t;
use crate::ssh::{RdpPointerEvent, SessionCommand, SessionEvent, SessionHandle};

const DEFAULT_RDP_PORT: u16 = 3389;
const DEFAULT_WIDTH: u16 = 1280;
const DEFAULT_HEIGHT: u16 = 800;
const READ_POLL: Duration = Duration::from_millis(50);

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
    commands: UnboundedReceiver<SessionCommand>,
    events: UnboundedSender<SessionEvent>,
) -> Result<()> {
    let host = session.host.trim().to_string();
    if host.is_empty() {
        bail!("{}", t("RDP 主机为空", "RDP host is empty"));
    }
    if session.user.trim().is_empty() {
        bail!("{}", t("RDP 用户名为空", "RDP username is empty"));
    }
    if session.password.is_empty() {
        bail!("{}", t("RDP 密码为空", "RDP password is empty"));
    }

    let port = if session.port == 0 {
        DEFAULT_RDP_PORT
    } else {
        session.port
    };
    let addr = format!("{host}:{port}");

    let _ = events.send(SessionEvent::Status(format!(
        "{} {} ...",
        t("RDP 连接中", "RDP connecting"),
        addr
    )));

    let stream = connect_transport(&session, &host, port, &events).await?;
    let std_stream = stream.into_std().context("convert RDP stream")?;
    std_stream
        .set_nonblocking(false)
        .context("set RDP stream blocking")?;
    std_stream
        .set_nodelay(true)
        .context("set RDP TCP_NODELAY")?;

    let blocking_events = events.clone();
    let join = tokio::task::spawn_blocking(move || {
        run_rdp_blocking(session, host, port, std_stream, commands, blocking_events)
    });

    join.await.context("RDP worker panicked")??;
    Ok(())
}

async fn connect_transport(
    session: &Session,
    host: &str,
    port: u16,
    events: &UnboundedSender<SessionEvent>,
) -> Result<TcpStream> {
    let addr = format!("{host}:{port}");
    match crate::proxy::resolve(&session.proxy) {
        Some(proxy) => {
            let _ = events.send(SessionEvent::Status(format!(
                "{} {} -> {}",
                t("经代理连接", "via proxy"),
                crate::proxy::describe(&proxy),
                addr
            )));
            crate::proxy::connect(&proxy, host, port)
                .await
                .with_context(|| format!("proxy connect to {addr} failed"))
        }
        None => TcpStream::connect(&addr)
            .await
            .with_context(|| format!("connect {addr} failed")),
    }
}

fn run_rdp_blocking(
    session: Session,
    host: String,
    port: u16,
    stream: StdTcpStream,
    mut commands: UnboundedReceiver<SessionCommand>,
    events: UnboundedSender<SessionEvent>,
) -> Result<()> {
    #[cfg(unix)]
    let readiness_probe = stream
        .try_clone()
        .context("clone RDP stream readiness probe")?;
    #[cfg(unix)]
    let read_fd = readiness_probe.as_raw_fd();

    let (domain, username) = split_rdp_user(&session.user);
    let mut connector = Connector::new()
        .screen(DEFAULT_WIDTH, DEFAULT_HEIGHT)
        .credentials(domain, username, session.password.as_str().to_string())
        .name("meatshell".to_string())
        .auto_logon(true)
        .check_certificate(false)
        .use_nla(true);

    let mut client = connector
        .connect(stream)
        .map_err(rdp_error)
        .with_context(|| format!("RDP connect {host}:{port}"))?;

    let _ = events.send(SessionEvent::Connected);
    let _ = events.send(SessionEvent::Status(format!(
        "{} {}:{}",
        t("RDP 已连接", "RDP connected"),
        host,
        port
    )));

    let mut frame = vec![0u8; usize::from(DEFAULT_WIDTH) * usize::from(DEFAULT_HEIGHT) * 4];
    emit_frame(&events, DEFAULT_WIDTH, DEFAULT_HEIGHT, &frame);

    loop {
        while let Ok(cmd) = commands.try_recv() {
            match cmd {
                SessionCommand::Close => {
                    let _ = client.shutdown();
                    let _ = events.send(SessionEvent::Closed(
                        t("RDP 连接已关闭", "RDP connection closed").into(),
                    ));
                    return Ok(());
                }
                SessionCommand::RdpKey {
                    text,
                    ctrl,
                    alt,
                    shift,
                } => {
                    for event in key_events(&text, ctrl, alt, shift) {
                        client.try_write(event).map_err(rdp_error)?;
                    }
                }
                SessionCommand::RdpPointer(event) => {
                    for event in pointer_events(event) {
                        client.try_write(event).map_err(rdp_error)?;
                    }
                }
                SessionCommand::Resize(_, _) | SessionCommand::RawInput(_) => {}
            }
        }

        #[cfg(unix)]
        {
            if !socket_readable(read_fd, READ_POLL)? {
                continue;
            }
        }

        #[cfg(not(unix))]
        std::thread::sleep(READ_POLL);

        let mut bitmaps = Vec::new();
        match client.read(|event| {
            if let RdpEvent::Bitmap(bitmap) = event {
                bitmaps.push(bitmap);
            }
        }) {
            Ok(()) => {
                let mut changed = false;
                for bitmap in bitmaps {
                    apply_bitmap(&mut frame, DEFAULT_WIDTH, DEFAULT_HEIGHT, bitmap)?;
                    changed = true;
                }
                if changed {
                    emit_frame(&events, DEFAULT_WIDTH, DEFAULT_HEIGHT, &frame);
                }
            }
            Err(RdpError::RdpError(err)) if err.kind() == RdpErrorKind::Disconnect => {
                let _ = events.send(SessionEvent::Closed(
                    t("RDP 服务端已断开", "RDP server disconnected").into(),
                ));
                return Ok(());
            }
            Err(err) => {
                let _ = events.send(SessionEvent::Closed(format!(
                    "{}: {:?}",
                    t("RDP 读取错误", "RDP read error"),
                    err
                )));
                return Ok(());
            }
        }

        #[cfg(unix)]
        let _keep_probe_alive = &readiness_probe;
    }
}

#[cfg(unix)]
fn socket_readable(fd: RawFd, timeout: Duration) -> Result<bool> {
    let mut poll_fd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    let ready = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
    if ready < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(err).context("poll RDP socket");
    }
    Ok(ready > 0 && (poll_fd.revents & libc::POLLIN) != 0)
}

fn rdp_error(err: RdpError) -> anyhow::Error {
    anyhow::anyhow!("{err:?}")
}

fn split_rdp_user(user: &str) -> (String, String) {
    let user = user.trim();
    if let Some((domain, name)) = user.split_once('\\') {
        (domain.trim().to_string(), name.trim().to_string())
    } else {
        (String::new(), user.to_string())
    }
}

fn emit_frame(events: &UnboundedSender<SessionEvent>, width: u16, height: u16, rgba: &[u8]) {
    let _ = events.send(SessionEvent::RdpFrame {
        width: u32::from(width),
        height: u32::from(height),
        rgba: rgba.to_vec(),
    });
}

fn apply_bitmap(
    frame: &mut [u8],
    screen_width: u16,
    screen_height: u16,
    bitmap: BitmapEvent,
) -> Result<()> {
    let left = usize::from(bitmap.dest_left);
    let right = usize::from(bitmap.dest_right);
    let top = usize::from(bitmap.dest_top);
    let bottom = usize::from(bitmap.dest_bottom);
    let screen_width = usize::from(screen_width);
    let screen_height = usize::from(screen_height);
    let source_width = usize::from(bitmap.width);
    let source_height = usize::from(bitmap.height);

    if right < left
        || bottom < top
        || right >= screen_width
        || bottom >= screen_height
        || frame.len() != screen_width * screen_height * 4
    {
        bail!("RDP bitmap update has invalid bounds");
    }

    let rect_width = right - left + 1;
    let rect_height = bottom - top + 1;
    let data = bitmap.decompress().map_err(rdp_error)?;
    if data.len() < source_width * source_height * 4
        || rect_width > source_width
        || rect_height > source_height
    {
        bail!("RDP bitmap update has invalid data size");
    }

    for row in 0..rect_height {
        for col in 0..rect_width {
            let src = (row * source_width + col) * 4;
            let dst = ((top + row) * screen_width + left + col) * 4;
            let b = data[src];
            let g = data[src + 1];
            let r = data[src + 2];
            let a = data[src + 3];
            frame[dst] = r;
            frame[dst + 1] = g;
            frame[dst + 2] = b;
            frame[dst + 3] = if a == 0 { 0xff } else { a };
        }
    }

    Ok(())
}

fn pointer_events(event: RdpPointerEvent) -> Vec<RdpEvent> {
    match event {
        RdpPointerEvent::Move { x, y } => vec![pointer_event(x, y, PointerButton::None, false)],
        RdpPointerEvent::Down { x, y, button } => {
            let button = pointer_button(button).unwrap_or(PointerButton::None);
            vec![pointer_event(x, y, button, true)]
        }
        RdpPointerEvent::Up { x, y, button } => {
            let button = pointer_button(button).unwrap_or(PointerButton::None);
            vec![pointer_event(x, y, button, false)]
        }
        // rdp-rs does not expose wheel input in its public RdpEvent type.
        RdpPointerEvent::Wheel { x, y, delta } => {
            let _ = delta;
            vec![pointer_event(x, y, PointerButton::None, false)]
        }
    }
}

fn pointer_event(x: u16, y: u16, button: PointerButton, down: bool) -> RdpEvent {
    RdpEvent::Pointer(PointerEvent { x, y, button, down })
}

fn pointer_button(button: u8) -> Option<PointerButton> {
    match button {
        1 => Some(PointerButton::Left),
        2 => Some(PointerButton::Middle),
        3 => Some(PointerButton::Right),
        _ => None,
    }
}

fn key_events(text: &str, ctrl: bool, alt: bool, shift: bool) -> Vec<RdpEvent> {
    if text.is_empty() {
        return Vec::new();
    }

    let mut events = Vec::new();
    for ch in text.chars() {
        if let Some(code) = special_scancode(ch) {
            push_key_chord(&mut events, code, ctrl, alt, shift);
        } else if let Some((code, needs_shift)) = char_scancode(ch) {
            push_key_chord(&mut events, code, ctrl, alt, shift || needs_shift);
        }
    }
    events
}

fn push_key_chord(events: &mut Vec<RdpEvent>, code: u16, ctrl: bool, alt: bool, shift: bool) {
    if ctrl {
        events.push(key_event(0x001d, true));
    }
    if alt {
        events.push(key_event(0x0038, true));
    }
    if shift {
        events.push(key_event(0x002a, true));
    }
    events.push(key_event(code, true));
    events.push(key_event(code, false));
    if shift {
        events.push(key_event(0x002a, false));
    }
    if alt {
        events.push(key_event(0x0038, false));
    }
    if ctrl {
        events.push(key_event(0x001d, false));
    }
}

fn key_event(code: u16, down: bool) -> RdpEvent {
    RdpEvent::Key(KeyboardEvent { code, down })
}

fn special_scancode(ch: char) -> Option<u16> {
    match ch {
        '\n' | '\r' => Some(0x001c),
        '\t' => Some(0x000f),
        '\u{0008}' => Some(0x000e),
        '\u{001b}' => Some(0x0001),
        '\u{F700}' => Some(0xe048),
        '\u{F701}' => Some(0xe050),
        '\u{F702}' => Some(0xe04b),
        '\u{F703}' => Some(0xe04d),
        '\u{F729}' => Some(0xe047),
        '\u{F72B}' => Some(0xe04f),
        '\u{F72C}' => Some(0xe049),
        '\u{F72D}' => Some(0xe051),
        '\u{F728}' => Some(0xe053),
        '\u{F704}' => Some(0x003b),
        '\u{F705}' => Some(0x003c),
        '\u{F706}' => Some(0x003d),
        '\u{F707}' => Some(0x003e),
        '\u{F708}' => Some(0x003f),
        '\u{F709}' => Some(0x0040),
        '\u{F70A}' => Some(0x0041),
        '\u{F70B}' => Some(0x0042),
        '\u{F70C}' => Some(0x0043),
        '\u{F70D}' => Some(0x0044),
        '\u{F70E}' => Some(0x0057),
        '\u{F70F}' => Some(0x0058),
        _ => None,
    }
}

fn char_scancode(ch: char) -> Option<(u16, bool)> {
    let lower = ch.to_ascii_lowercase();
    let code = match lower {
        'a' => 0x001e,
        'b' => 0x0030,
        'c' => 0x002e,
        'd' => 0x0020,
        'e' => 0x0012,
        'f' => 0x0021,
        'g' => 0x0022,
        'h' => 0x0023,
        'i' => 0x0017,
        'j' => 0x0024,
        'k' => 0x0025,
        'l' => 0x0026,
        'm' => 0x0032,
        'n' => 0x0031,
        'o' => 0x0018,
        'p' => 0x0019,
        'q' => 0x0010,
        'r' => 0x0013,
        's' => 0x001f,
        't' => 0x0014,
        'u' => 0x0016,
        'v' => 0x002f,
        'w' => 0x0011,
        'x' => 0x002d,
        'y' => 0x0015,
        'z' => 0x002c,
        '1' | '!' => 0x0002,
        '2' | '@' => 0x0003,
        '3' | '#' => 0x0004,
        '4' | '$' => 0x0005,
        '5' | '%' => 0x0006,
        '6' | '^' => 0x0007,
        '7' | '&' => 0x0008,
        '8' | '*' => 0x0009,
        '9' | '(' => 0x000a,
        '0' | ')' => 0x000b,
        '-' | '_' => 0x000c,
        '=' | '+' => 0x000d,
        '[' | '{' => 0x001a,
        ']' | '}' => 0x001b,
        '\\' | '|' => 0x002b,
        ';' | ':' => 0x0027,
        '\'' | '"' => 0x0028,
        '`' | '~' => 0x0029,
        ',' | '<' => 0x0033,
        '.' | '>' => 0x0034,
        '/' | '?' => 0x0035,
        ' ' => 0x0039,
        _ => return None,
    };
    let needs_shift = ch.is_ascii_uppercase() || matches!(
        ch,
        '!' | '@'
            | '#'
            | '$'
            | '%'
            | '^'
            | '&'
            | '*'
            | '('
            | ')'
            | '_'
            | '+'
            | '{'
            | '}'
            | '|'
            | ':'
            | '"'
            | '~'
            | '<'
            | '>'
            | '?'
    );
    Some((code, needs_shift))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_windows_domain_user() {
        assert_eq!(split_rdp_user("ACME\\alice"), ("ACME".to_string(), "alice".to_string()));
        assert_eq!(split_rdp_user("alice"), (String::new(), "alice".to_string()));
    }

    #[test]
    fn maps_special_keys() {
        assert_eq!(special_scancode('\n'), Some(0x001c));
        assert_eq!(special_scancode('\u{F703}'), Some(0xe04d));
    }

    #[test]
    fn maps_us_keyboard_chars() {
        assert_eq!(char_scancode('a'), Some((0x001e, false)));
        assert_eq!(char_scancode('A'), Some((0x001e, true)));
        assert_eq!(char_scancode('?'), Some((0x0035, true)));
    }

    #[test]
    fn applies_bgra_bitmap_to_rgba_frame() {
        let bitmap = BitmapEvent {
            dest_left: 1,
            dest_top: 0,
            dest_right: 1,
            dest_bottom: 0,
            width: 1,
            height: 1,
            bpp: 32,
            is_compress: false,
            data: vec![10, 20, 30, 0],
        };
        let mut frame = vec![0; 2 * 1 * 4];
        apply_bitmap(&mut frame, 2, 1, bitmap).unwrap();
        assert_eq!(&frame[4..8], &[30, 20, 10, 255]);
    }
}
