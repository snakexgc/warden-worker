use log::{Level, LevelFilter, Log, Metadata, Record};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::RwLock;
use worker::Env;

pub const LOG_LEVEL_VAR: &str = "LOG_LEVEL";
pub const DEFAULT_LOG_LEVEL: Level = Level::Info;

static MODULE_LOGGER: Lazy<ModuleLogger> = Lazy::new(ModuleLogger::new);

struct ModuleLogger {
    global_level: RwLock<LevelFilter>,
    module_levels: RwLock<HashMap<String, LevelFilter>>,
}

impl ModuleLogger {
    fn new() -> Self {
        Self {
            global_level: RwLock::new(DEFAULT_LOG_LEVEL.to_level_filter()),
            module_levels: RwLock::new(HashMap::new()),
        }
    }

    fn configure(&self, global_level: LevelFilter, module_levels: HashMap<String, LevelFilter>) {
        if let Ok(mut gl) = self.global_level.write() {
            *gl = global_level;
        }
        if let Ok(mut ml) = self.module_levels.write() {
            *ml = module_levels;
        }
    }
}

impl Log for ModuleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        let target = metadata.target();
        let level = metadata.level();

        let global_level = self
            .global_level
            .read()
            .map(|g| *g)
            .unwrap_or(DEFAULT_LOG_LEVEL.to_level_filter());

        let module_levels = self.module_levels.read();

        if let Ok(ml) = module_levels {
            if let Some((module, _)) = ml
                .iter()
                .find(|(module, _)| target.starts_with(*module) || target == **module)
            {
                if let Some(module_level) = ml.get(module) {
                    return level <= *module_level;
                }
            }
        }

        level <= global_level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let target = record.target();
            let level = record.level();
            let args = record.args();
            web_sys::console::log_1(&format!("[{}][{}] {}", target, level, args).into());
        }
    }

    fn flush(&self) {}
}

pub fn init_logging(env: &Env) -> Level {
    let (global_level, module_levels) = parse_log_config(env);

    MODULE_LOGGER.configure(global_level, module_levels);

    let static_logger: &'static dyn Log = &*MODULE_LOGGER;

    if log::set_logger(static_logger).is_err() {
        web_sys::console::log_1(&"Logger already set, reconfiguring...".into());
    }
    log::set_max_level(global_level);

    global_level.to_level().unwrap_or(DEFAULT_LOG_LEVEL)
}

fn parse_log_config(env: &Env) -> (LevelFilter, HashMap<String, LevelFilter>) {
    let config_str = match env.var(LOG_LEVEL_VAR) {
        Ok(var) => var.to_string(),
        Err(_) => return (DEFAULT_LOG_LEVEL.to_level_filter(), HashMap::new()),
    };

    parse_level_string(&config_str)
}

fn parse_level_string(s: &str) -> (LevelFilter, HashMap<String, LevelFilter>) {
    let parts: Vec<&str> = s.split(',').collect();

    if parts.is_empty() {
        return (DEFAULT_LOG_LEVEL.to_level_filter(), HashMap::new());
    }

    let global_level =
        parse_single_level(parts[0].trim()).unwrap_or(DEFAULT_LOG_LEVEL.to_level_filter());

    let mut module_levels = HashMap::new();

    for part in parts.iter().skip(1) {
        let part = part.trim();
        if let Some((module, level_str)) = part.split_once('=') {
            let module = module.trim();
            let level_str = level_str.trim();
            if let Some(level) = parse_single_level(level_str) {
                module_levels.insert(module.to_string(), level);
            }
        }
    }

    (global_level, module_levels)
}

fn parse_single_level(s: &str) -> Option<LevelFilter> {
    match s.to_lowercase().as_str() {
        "off" => Some(LevelFilter::Off),
        "error" => Some(LevelFilter::Error),
        "warn" => Some(LevelFilter::Warn),
        "info" => Some(LevelFilter::Info),
        "debug" => Some(LevelFilter::Debug),
        "trace" => Some(LevelFilter::Trace),
        _ => None,
    }
}

pub mod targets {
    #[allow(dead_code)]
    pub const REQUEST: &str = "request";
    #[allow(dead_code)]
    pub const RESPONSE: &str = "response";
    pub const AUTH: &str = "auth";
    pub const API: &str = "api";
    pub const DB: &str = "db";
    #[allow(dead_code)]
    pub const CRYPTO: &str = "crypto";
    pub const EXTERNAL: &str = "external";
    #[allow(dead_code)]
    pub const ERROR: &str = "error";
    #[allow(dead_code)]
    pub const PANIC: &str = "panic";
}

#[macro_export]
macro_rules! log_request {
    ($($arg:tt)*) => {
        log::info!(target: $crate::logging::targets::REQUEST, $($arg)*)
    };
}

#[macro_export]
macro_rules! log_response {
    ($($arg:tt)*) => {
        log::info!(target: $crate::logging::targets::RESPONSE, $($arg)*)
    };
}

#[macro_export]
macro_rules! log_auth {
    ($($arg:tt)*) => {
        log::info!(target: $crate::logging::targets::AUTH, $($arg)*)
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        log::error!(target: $crate::logging::targets::ERROR, $($arg)*)
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        log::warn!(target: $crate::logging::targets::ERROR, $($arg)*)
    };
}

#[macro_export]
macro_rules! log_api {
    ($($arg:tt)*) => {
        log::debug!(target: $crate::logging::targets::API, $($arg)*)
    };
}

#[macro_export]
macro_rules! log_db {
    ($($arg:tt)*) => {
        log::debug!(target: $crate::logging::targets::DB, $($arg)*)
    };
}

#[macro_export]
macro_rules! log_crypto {
    ($($arg:tt)*) => {
        log::debug!(target: $crate::logging::targets::CRYPTO, $($arg)*)
    };
}

#[macro_export]
macro_rules! log_external {
    ($($arg:tt)*) => {
        log::info!(target: $crate::logging::targets::EXTERNAL, $($arg)*)
    };
}
