//! Shared cross-process structured diagnostic logger + lock-free live probe progress tracker.
//!
//! - Both Android processes (`app.velox.vpn` UI and `app.velox.vpn:vpn` tunnel service) append
//!   single-line entries via kernel-atomic `O_APPEND` to `{data_dir}/velox_diag.log`, rolling over
//!   cleanly to `velox_diag.prev.log` at 96 KiB so disk/RAM footprint stays tiny while retaining
//!   ~500 detailed, local-timezone-stamped entries across sessions and crashes.
//! - Format: `[HH:MM:SS.mmm] [LVL] [TAG] message` where `LVL` in `{INFO, OK, WARN, ERR}`.
//! - `PROBE_PROGRESS` exposes atomic counters (`done`, `total`, `alive`, `eta_sec`, `stage`)
//!   polled by Kotlin to display real-time connection progress & remaining-time (ETA) countdowns.

use once_cell::sync::Lazy;
use serde_json::json;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_LOG_FILE_BYTES: u64 = 96 * 1024;
const MAX_MEM_FALLBACK_LINES: usize = 250;

static LOG_DIR: Lazy<RwLock<Option<PathBuf>>> = Lazy::new(|| RwLock::new(None));
static LOG_APPROX_BYTES: AtomicU64 = AtomicU64::new(0);
static MEM_FALLBACK: Lazy<Mutex<Vec<String>>> = Lazy::new(|| Mutex::new(Vec::new()));

pub fn set_log_dir(dir: PathBuf) {
    let _ = fs::create_dir_all(&dir);
    let cur_len = fs::metadata(dir.join("velox_diag.log"))
        .map(|m| m.len())
        .unwrap_or(0);
    LOG_APPROX_BYTES.store(cur_len, Ordering::Relaxed);
    if let Ok(mut g) = LOG_DIR.write() {
        *g = Some(dir);
    }
}

/// Redact a subscription or proxy URL so secret path tokens, query keys, passwords, and
/// `happ://crypt*` blobs NEVER leak into diagnostic logs or exported log reports!
pub fn redact_url_for_log(raw: &str) -> String {
    let s = raw.trim();
    for scheme in [
        "happ://crypt5/",
        "happ://crypt4/",
        "happ://crypt3/",
        "happ://crypt2/",
        "happ://crypt/",
        "incy://crypt1/",
        "v2raytun://crypt/",
    ] {
        if s.len() >= scheme.len() && s[..scheme.len()].eq_ignore_ascii_case(scheme) {
            return format!("{scheme}***");
        }
    }
    if let Ok(u) = url::Url::parse(s) {
        let scheme = u.scheme();
        let host = u.host_str().unwrap_or("unknown");
        let port_sfx = u
            .port()
            .filter(|p| !((scheme == "https" && *p == 443) || (scheme == "http" && *p == 80)))
            .map(|p| format!(":{p}"))
            .unwrap_or_default();
        if matches!(scheme, "http" | "https" | "ssconf") {
            let segs: Vec<&str> = u.path().split('/').filter(|p| !p.is_empty()).collect();
            let safe_path = match segs.as_slice() {
                [] => String::new(),
                [first] if first.len() <= 8 => format!("/{first}"),
                [_secret] => "/***".to_string(),
                [first, ..] if first.len() <= 12 => format!("/{first}/***"),
                _ => "/***".to_string(),
            };
            let q_sfx = if u.query().is_some() { "?***" } else { "" };
            return format!("{scheme}://{host}{port_sfx}{safe_path}{q_sfx}");
        }
        return format!("{scheme}://{host}{port_sfx}/***");
    }
    s.chars().take(48).collect()
}

/// Automatically scrub any accidental `happ://crypt*`, `incy://crypt*`, or share-URI credentials
/// embedded inside a free-form log message.
fn redact_inline_secrets(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for tok in input.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        let low = tok.to_ascii_lowercase();
        if low.starts_with("happ://crypt")
            || low.starts_with("incy://crypt")
            || low.starts_with("v2raytun://crypt")
            || low.starts_with("vless://")
            || low.starts_with("vmess://")
            || low.starts_with("trojan://")
            || low.starts_with("hy2://")
            || low.starts_with("hysteria2://")
            || low.starts_with("ss://")
            || low.starts_with("ssconf://")
        {
            out.push_str(&redact_url_for_log(tok));
        } else {
            out.push_str(tok);
        }
    }
    out
}

/// Cross-process race-free atomic file write using POSIX `flock(LOCK_EX)` on `{dst}.lock`
/// and a PID-unique temporary file (`{name}.{pid}.tmp`) + atomic `rename()`.
/// Prevents `app.velox.vpn` (UI) and `app.velox.vpn:vpn` (tunnel) from ever clobbering state!
pub fn write_file_atomic_locked(dst: &Path, bytes: &[u8]) -> bool {
    let Some(parent) = dst.parent() else {
        return false;
    };
    let _ = fs::create_dir_all(parent);
    let fname = dst
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("state.json");

    #[cfg(unix)]
    let _lock_guard = {
        use std::os::unix::io::AsRawFd;
        let lock_path = parent.join(format!(".{fname}.lock"));
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .ok()
            .map(|lf| {
                unsafe {
                    let _ = libc::flock(lf.as_raw_fd(), libc::LOCK_EX);
                }
                lf
            })
    };

    let pid = std::process::id();
    let tmp = parent.join(format!(".{fname}.{pid}.tmp"));
    if fs::write(&tmp, bytes).is_err() {
        let _ = fs::remove_file(&tmp);
        return false;
    }
    if fs::rename(&tmp, dst).is_err() {
        let ok = fs::write(dst, bytes).is_ok();
        let _ = fs::remove_file(&tmp);
        return ok;
    }
    true
}

/// Format local wall-clock `[HH:MM:SS.mmm]` using POSIX `localtime_r` (matches user's phone clock).
fn local_timestamp_ms() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();

    #[cfg(unix)]
    unsafe {
        let t = secs as libc::time_t;
        let mut tm: libc::tm = std::mem::zeroed();
        if !libc::localtime_r(&t, &mut tm).is_null() {
            return format!(
                "{:02}:{:02}:{:02}.{:03}",
                tm.tm_hour, tm.tm_min, tm.tm_sec, millis
            );
        }
    }

    let s = secs % 86400;
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        s / 3600,
        (s % 3600) / 60,
        s % 60,
        millis
    )
}

fn sanitize_single_line(s: &str, max_chars: usize) -> String {
    s.chars()
        .map(|c| if c == '\n' || c == '\r' || c == '\t' { ' ' } else { c })
        .filter(|c| !c.is_control())
        .take(max_chars)
        .collect::<String>()
        .trim()
        .to_string()
}

pub fn diag_log(level: &str, tag: &str, msg: impl AsRef<str>) {
    let lvl = match level.to_ascii_uppercase().as_str() {
        "OK" => "OK",
        "WARN" | "WARNING" => "WARN",
        "ERR" | "ERROR" => "ERR",
        _ => "INFO",
    };
    let clean_tag = sanitize_single_line(tag, 12);
    let tag_final = if clean_tag.is_empty() { "SYS" } else { &clean_tag };
    let scrubbed = redact_inline_secrets(msg.as_ref());
    let clean_msg = sanitize_single_line(&scrubbed, 420);
    if clean_msg.is_empty() {
        return;
    }

    let line = format!("[{}] [{}] [{}] {}", local_timestamp_ms(), lvl, tag_final, clean_msg);

    let dir_opt = LOG_DIR.read().ok().and_then(|g| g.clone());
    if let Some(dir) = dir_opt {
        let cur = dir.join("velox_diag.log");
        let add_len = (line.len() + 1) as u64;
        // Zero-syscall fast path: only call `fs::metadata()` when atomic counter hits rollover!
        let est = LOG_APPROX_BYTES.fetch_add(add_len, Ordering::Relaxed) + add_len;
        if est >= MAX_LOG_FILE_BYTES {
            let real_len = fs::metadata(&cur).map(|m| m.len()).unwrap_or(0);
            if real_len >= MAX_LOG_FILE_BYTES {
                let prev = dir.join("velox_diag.prev.log");
                let _ = fs::rename(&cur, &prev);
                LOG_APPROX_BYTES.store(add_len, Ordering::Relaxed);
            } else {
                LOG_APPROX_BYTES.store(real_len + add_len, Ordering::Relaxed);
            }
        }
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&cur) {
            let mut bytes = line.into_bytes();
            bytes.push(b'\n');
            let _ = f.write_all(&bytes);
            return;
        }
    }

    if let Ok(mut mem) = MEM_FALLBACK.lock() {
        mem.push(line);
        if mem.len() > MAX_MEM_FALLBACK_LINES {
            let drain = mem.len() - MAX_MEM_FALLBACK_LINES;
            mem.drain(0..drain);
        }
    }
}

pub fn diag_info(tag: &str, msg: impl AsRef<str>) {
    diag_log("INFO", tag, msg);
}

pub fn diag_ok(tag: &str, msg: impl AsRef<str>) {
    diag_log("OK", tag, msg);
}

pub fn diag_warn(tag: &str, msg: impl AsRef<str>) {
    diag_log("WARN", tag, msg);
}

pub fn diag_err(tag: &str, msg: impl AsRef<str>) {
    diag_log("ERR", tag, msg);
}

/// Read up to `max_lines` most recent log lines across `velox_diag.prev.log` + `velox_diag.log`.
pub fn read_diag_logs(max_lines: usize) -> Vec<String> {
    let cap = max_lines.clamp(20, 600);
    let dir_opt = LOG_DIR.read().ok().and_then(|g| g.clone());
    if let Some(dir) = dir_opt {
        let cur = dir.join("velox_diag.log");
        let prev = dir.join("velox_diag.prev.log");
        let cur_text = fs::read_to_string(&cur).unwrap_or_default();
        let cur_lines: Vec<&str> = cur_text.lines().filter(|l| !l.trim().is_empty()).collect();

        if cur_lines.len() >= cap {
            return cur_lines[cur_lines.len() - cap..]
                .iter()
                .map(|s| (*s).to_string())
                .collect();
        }

        let mut out = Vec::with_capacity(cap);
        if let Ok(prev_text) = fs::read_to_string(&prev) {
            let prev_lines: Vec<&str> =
                prev_text.lines().filter(|l| !l.trim().is_empty()).collect();
            let need = cap - cur_lines.len();
            let start = prev_lines.len().saturating_sub(need);
            for l in &prev_lines[start..] {
                out.push((*l).to_string());
            }
        }
        for l in cur_lines {
            out.push(l.to_string());
        }
        return out;
    }

    MEM_FALLBACK
        .lock()
        .map(|m| {
            let start = m.len().saturating_sub(cap);
            m[start..].to_vec()
        })
        .unwrap_or_default()
}

pub fn clear_diag_logs() {
    let dir_opt = LOG_DIR.read().ok().and_then(|g| g.clone());
    if let Some(dir) = dir_opt {
        let _ = fs::remove_file(dir.join("velox_diag.prev.log"));
        let _ = fs::write(dir.join("velox_diag.log"), b"");
    }
    LOG_APPROX_BYTES.store(0, Ordering::Relaxed);
    if let Ok(mut mem) = MEM_FALLBACK.lock() {
        mem.clear();
    }
    diag_info("SYS", "Журнал диагностики очищен пользователем");
}

/// Short host:port label safe for diagnostics.
pub fn fmt_endpoint(host: &str, port: u16) -> String {
    let h: String = host.chars().take(42).collect();
    format!("{h}:{port}")
}

// ---------------------------------------------------------------------------
// Real-time atomic connection / batch-probe progress & ETA tracker
// ---------------------------------------------------------------------------

pub struct LiveProbeProgress {
    active: AtomicBool,
    stage_idx: AtomicU32,
    stage_total: AtomicU32,
    done: AtomicU32,
    total: AtomicU32,
    alive: AtomicU32,
    percent: AtomicU32,
    eta_sec: AtomicU32,
    detail: Mutex<String>,
}

pub static PROBE_PROGRESS: Lazy<LiveProbeProgress> = Lazy::new(|| LiveProbeProgress {
    active: AtomicBool::new(false),
    stage_idx: AtomicU32::new(0),
    stage_total: AtomicU32::new(5),
    done: AtomicU32::new(0),
    total: AtomicU32::new(0),
    alive: AtomicU32::new(0),
    percent: AtomicU32::new(0),
    eta_sec: AtomicU32::new(0),
    detail: Mutex::new(String::new()),
});

impl LiveProbeProgress {
    pub fn set_stage(
        &self,
        stage_idx: u32,
        stage_total: u32,
        percent: u32,
        eta_sec: u32,
        done: u32,
        total: u32,
        alive: u32,
        detail: impl Into<String>,
    ) {
        self.active.store(true, Ordering::Relaxed);
        self.stage_idx.store(stage_idx, Ordering::Relaxed);
        self.stage_total.store(stage_total.max(1), Ordering::Relaxed);
        self.percent.store(percent.min(99), Ordering::Relaxed);
        self.eta_sec.store(eta_sec, Ordering::Relaxed);
        self.done.store(done, Ordering::Relaxed);
        self.total.store(total, Ordering::Relaxed);
        self.alive.store(alive, Ordering::Relaxed);
        if let Ok(mut d) = self.detail.lock() {
            *d = detail.into();
        }
    }

    pub fn tick_item(
        &self,
        base_pct: u32,
        span_pct: u32,
        max_stage_sec: u32,
        tail_sec: u32,
        is_alive: bool,
        label_prefix: &str,
    ) -> (u32, u32, u32) {
        let done = self.done.fetch_add(1, Ordering::Relaxed) + 1;
        let alive = if is_alive {
            self.alive.fetch_add(1, Ordering::Relaxed) + 1
        } else {
            self.alive.load(Ordering::Relaxed)
        };
        let total = self.total.load(Ordering::Relaxed).max(1);
        let frac = (done as f32 / total as f32).clamp(0.0, 1.0);
        let pct = (base_pct + (span_pct as f32 * frac) as u32).min(98);
        let rem_stage = ((1.0 - frac) * max_stage_sec as f32).ceil() as u32;
        let eta = (rem_stage + tail_sec).max(1);
        self.percent.store(pct, Ordering::Relaxed);
        self.eta_sec.store(eta, Ordering::Relaxed);
        if let Ok(mut d) = self.detail.lock() {
            *d = format!("{label_prefix}: {done}/{total} · живых: {alive}");
        }
        (done, total, alive)
    }

    pub fn finish(&self) {
        self.active.store(false, Ordering::Relaxed);
        self.percent.store(100, Ordering::Relaxed);
        self.eta_sec.store(0, Ordering::Relaxed);
    }

    pub fn to_json(&self) -> String {
        let detail = self.detail.lock().map(|d| d.clone()).unwrap_or_default();
        json!({
            "active": self.active.load(Ordering::Relaxed),
            "stageIdx": self.stage_idx.load(Ordering::Relaxed),
            "stageTotal": self.stage_total.load(Ordering::Relaxed),
            "percent": self.percent.load(Ordering::Relaxed),
            "etaSec": self.eta_sec.load(Ordering::Relaxed),
            "done": self.done.load(Ordering::Relaxed),
            "total": self.total.load(Ordering::Relaxed),
            "alive": self.alive.load(Ordering::Relaxed),
            "detail": detail,
        })
        .to_string()
    }
}
