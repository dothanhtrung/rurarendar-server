use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use web_misc::db::DBConfig;

#[derive(Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub db: DBConfig,
    pub bind: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            db: DBConfig::default(),
            bind: "127.0.0.1:8080".into(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            let config = Self::default();
            let text = ron::ser::to_string_pretty(&config, ron::ser::PrettyConfig::default())?;
            std::fs::write(path, text).with_context(|| format!("Could not create {}", path.display()))?;
            anyhow::bail!("Created {}; configure the database, then restart the server.", path.display());
        }
        let text = std::fs::read_to_string(path).with_context(|| format!("Could not read {}", path.display()))?;
        ron::from_str(&text).with_context(|| format!("Invalid config in {}", path.display()))
    }
}