use std::collections::HashMap;
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub server_host: String,
    pub server_port: u16,
    /// Public URL of the instance (e.g. `https://vault.example.com`). Its
    /// origin is the only one allowed to make state-changing API calls.
    pub server_url: String,
    /// Sign-ups are closed unless explicitly enabled.
    pub allow_registration: bool,
    /// Trust the right-most `X-Forwarded-For` hop as the client IP. Enable
    /// only when the backend is reachable exclusively through a reverse proxy
    /// (Caddy, nginx) that sets this header.
    pub trust_proxy: bool,
    /// Extra origins allowed for API calls (development only).
    pub extra_origins: Vec<String>,
    /// When set, sign-ups also require this invitation code.
    pub registration_code: Option<String>,
}

impl ServerConfig {
    pub fn is_https(&self) -> bool {
        self.server_url.starts_with("https://")
    }

    /// `scheme://host[:port]` of `server_url`.
    pub fn origin(&self) -> String {
        origin_of(&self.server_url)
    }

    pub fn allowed_origins(&self) -> Vec<String> {
        let mut origins = vec![self.origin()];
        origins.extend(self.extra_origins.iter().map(|o| origin_of(o)));
        origins
    }
}

pub fn origin_of(url: &str) -> String {
    let trimmed = url.trim().trim_end_matches('/');
    match trimmed.find("://") {
        Some(idx) => {
            let rest = &trimmed[idx + 3..];
            let host_end = rest.find('/').unwrap_or(rest.len());
            format!("{}://{}", &trimmed[..idx].to_ascii_lowercase(), &rest[..host_end].to_ascii_lowercase())
        }
        None => trimmed.to_ascii_lowercase(),
    }
}

pub fn default_config() -> ServerConfig {
    ServerConfig {
        server_host: "127.0.0.1".into(),
        server_port: 58951,
        server_url: "http://localhost:58951".into(),
        allow_registration: false,
        trust_proxy: false,
        extra_origins: Vec::new(),
        registration_code: None,
    }
}

/// Parses common boolean spellings: `1/true/yes/y/on/enabled` and
/// `0/false/no/n/off/disabled`.
pub fn parse_bool_flag(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "y" | "on" | "enable" | "enabled" => Some(true),
        "0" | "false" | "no" | "n" | "off" | "disable" | "disabled" => Some(false),
        _ => None,
    }
}

fn parse_json_bool(value: &serde_json::Value) -> Option<bool> {
    if let Some(flag) = value.as_bool() {
        return Some(flag);
    }
    if let Some(number) = value.as_u64() {
        return Some(number != 0);
    }
    value.as_str().and_then(parse_bool_flag)
}

/// Reads a `.env` file into a map (no process-environment mutation). Only an
/// explicit `XVAULT_ENV_PATH`, or `.env` in the working directory, is read.
fn read_dotenv() -> HashMap<String, String> {
    let mut values = HashMap::new();
    let path = env::var("XVAULT_ENV_PATH")
        .ok()
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".env"));
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return values;
    };
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let mut value = value.trim().to_string();
        if !(value.starts_with('"') || value.starts_with('\'')) {
            if let Some((before, _)) = value.split_once(" #") {
                value = before.trim_end().to_string();
            }
        }
        if value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')))
        {
            value = value[1..value.len() - 1].to_string();
        }
        values.insert(key.to_string(), value);
    }
    values
}

/// Environment lookup: real environment variables win over `.env`.
struct Env {
    dotenv: HashMap<String, String>,
}

impl Env {
    fn get(&self, key: &str) -> Option<String> {
        env::var(key)
            .ok()
            .or_else(|| self.dotenv.get(key).cloned())
            .filter(|v| !v.is_empty())
    }
}

/// Loads `config.json` (if present) then applies environment overrides.
/// Any malformed value is a hard error: the server refuses to start rather
/// than silently falling back to defaults.
pub fn load_config(path: &str) -> Result<ServerConfig, String> {
    let env = Env { dotenv: read_dotenv() };
    let mut config = default_config();

    if let Ok(contents) = std::fs::read_to_string(path) {
        let parsed: serde_json::Value = serde_json::from_str(&contents)
            .map_err(|err| format!("invalid config file {path}: {err}"))?;
        if let Some(host) = parsed.get("SERVER_HOST").and_then(|v| v.as_str()) {
            if !host.is_empty() {
                config.server_host = host.to_string();
            }
        }
        if let Some(port) = parsed.get("SERVER_PORT") {
            let port = port
                .as_u64()
                .filter(|p| (1..=65535).contains(p))
                .ok_or_else(|| format!("invalid SERVER_PORT in {path}"))?;
            config.server_port = port as u16;
        }
        if let Some(url) = parsed.get("SERVER_URL").and_then(|v| v.as_str()) {
            if !url.is_empty() {
                config.server_url = url.to_string();
            }
        }
        for key in ["ALLOW_REGISTRATION", "XVAULT_ALLOW_REGISTRATION"] {
            if let Some(value) = parsed.get(key) {
                config.allow_registration =
                    parse_json_bool(value).ok_or_else(|| format!("invalid {key} in {path}"))?;
            }
        }
        for key in ["DISABLE_REGISTRATION", "XVAULT_DISABLE_REGISTRATION"] {
            if let Some(value) = parsed.get(key) {
                let disabled =
                    parse_json_bool(value).ok_or_else(|| format!("invalid {key} in {path}"))?;
                config.allow_registration = !disabled;
            }
        }
        if let Some(value) = parsed.get("TRUST_PROXY") {
            config.trust_proxy =
                parse_json_bool(value).ok_or_else(|| format!("invalid TRUST_PROXY in {path}"))?;
        }
        if let Some(code) = parsed.get("REGISTRATION_CODE").and_then(|v| v.as_str()) {
            config.registration_code = Some(code.trim().to_string()).filter(|c| !c.is_empty());
        }
        if let Some(list) = parsed.get("ALLOWED_ORIGINS").and_then(|v| v.as_array()) {
            config.extra_origins = list
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
        }
    }

    if let Some(host) = env.get("SERVER_HOST") {
        config.server_host = host;
    }
    if let Some(port) = env.get("SERVER_PORT") {
        config.server_port = port
            .parse::<u16>()
            .ok()
            .filter(|p| *p > 0)
            .ok_or_else(|| format!("invalid SERVER_PORT: {port}"))?;
    }
    if let Some(url) = env.get("SERVER_URL") {
        config.server_url = url;
    }
    for key in ["ALLOW_REGISTRATION", "XVAULT_ALLOW_REGISTRATION"] {
        if let Some(raw) = env.get(key) {
            config.allow_registration =
                parse_bool_flag(&raw).ok_or_else(|| format!("invalid {key}: {raw}"))?;
        }
    }
    for key in ["DISABLE_REGISTRATION", "XVAULT_DISABLE_REGISTRATION"] {
        if let Some(raw) = env.get(key) {
            config.allow_registration =
                !parse_bool_flag(&raw).ok_or_else(|| format!("invalid {key}: {raw}"))?;
        }
    }
    if let Some(raw) = env.get("TRUST_PROXY") {
        config.trust_proxy = parse_bool_flag(&raw).ok_or_else(|| format!("invalid TRUST_PROXY: {raw}"))?;
    }
    if let Some(code) = env.get("REGISTRATION_CODE") {
        config.registration_code = Some(code.trim().to_string()).filter(|c| !c.is_empty());
    }
    if config.registration_code.as_ref().is_some_and(|c| c.len() < 16) {
        return Err("REGISTRATION_CODE must be at least 16 characters".into());
    }
    if let Some(raw) = env.get("ALLOWED_ORIGINS") {
        config.extra_origins = raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    }

    if !(config.server_url.starts_with("http://") || config.server_url.starts_with("https://")) {
        return Err(format!("SERVER_URL must start with http:// or https:// (got {})", config.server_url));
    }

    Ok(config)
}

/// SQLite database path: `XVAULT_DB_PATH` env var, else `./data/xVault.sqlite`.
pub fn resolve_db_path() -> PathBuf {
    if let Ok(path) = env::var("XVAULT_DB_PATH") {
        return PathBuf::from(path);
    }
    PathBuf::from("data").join("xVault.sqlite")
}

/// Static assets directory: `XVAULT_DIST_DIR`, then `./dist`, then `../dist`.
pub fn resolve_dist_dir() -> PathBuf {
    if let Ok(path) = env::var("XVAULT_DIST_DIR") {
        return PathBuf::from(path);
    }
    for candidate in [PathBuf::from("dist"), PathBuf::from("../dist")] {
        if candidate.join("index.html").is_file() {
            return candidate;
        }
    }
    PathBuf::from("dist")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_parsing() {
        assert_eq!(origin_of("https://Vault.Example.com/"), "https://vault.example.com");
        assert_eq!(origin_of("http://localhost:58951/app"), "http://localhost:58951");
    }

    #[test]
    fn registration_closed_by_default() {
        assert!(!default_config().allow_registration);
    }
}
