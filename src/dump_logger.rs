use std::{
    os::raw::{c_char, c_void},
    sync::Mutex,
};

pub(crate) static DUMP_CALLBACK: Mutex<Option<DumpCallback>> = Mutex::new(None);

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum LogLevel {
    Off = 0,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<log::LevelFilter> for LogLevel {
    fn from(level: log::LevelFilter) -> Self {
        match level {
            log::LevelFilter::Off => LogLevel::Off,
            log::LevelFilter::Error => LogLevel::Error,
            log::LevelFilter::Warn => LogLevel::Warn,
            log::LevelFilter::Info => LogLevel::Info,
            log::LevelFilter::Debug => LogLevel::Debug,
            log::LevelFilter::Trace => LogLevel::Trace,
        }
    }
}

/// # Safety
///
/// set dump log info callback.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tun2proxy_set_log_callback(
    callback: Option<unsafe extern "C" fn(LogLevel, *const c_char, *mut c_void)>,
    ctx: *mut c_void,
) {
    *DUMP_CALLBACK.lock().unwrap() = Some(DumpCallback(callback, ctx));
}

#[derive(Clone)]
pub struct DumpCallback(Option<unsafe extern "C" fn(LogLevel, *const c_char, *mut c_void)>, *mut c_void);

impl DumpCallback {
    unsafe fn call(self, dump_level: LogLevel, info: *const c_char) {
        if let Some(cb) = self.0 {
            unsafe { cb(dump_level, info, self.1) };
        }
    }
}

unsafe impl Send for DumpCallback {}
unsafe impl Sync for DumpCallback {}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DumpLogger {}

impl log::Log for DumpLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Trace
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let current_crate_name = env!("CARGO_CRATE_NAME");
            if record.module_path().unwrap_or("").starts_with(current_crate_name) {
                self.do_dump_log(record);
            }
        }
    }

    fn flush(&self) {}
}

fn utc_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    // Howard Hinnant civil_from_days: days since 1970-01-01 -> UTC Y-M-D
    let z = secs as i64 / 86400 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + if m <= 2 { 1 } else { 0 };
    let tod = secs % 86400;
    let hh = tod / 3600;
    let mm = (tod % 3600) / 60;
    let ss = tod % 60;
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02}")
}

impl DumpLogger {
    fn do_dump_log(&self, record: &log::Record) {
        let msg = format!(
            "[{} {:<5} {}] - {}",
            utc_timestamp(),
            record.level(),
            record.module_path().unwrap_or(""),
            record.args()
        );
        let c_msg = std::ffi::CString::new(msg).unwrap();
        let ptr = c_msg.as_ptr();
        if let Some(cb) = DUMP_CALLBACK.lock().unwrap().clone() {
            unsafe {
                cb.call(record.level().to_level_filter().into(), ptr);
            }
        }
    }
}
