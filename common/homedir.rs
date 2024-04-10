//! State-directory handling.

use std::path::PathBuf;
use anyhow::Result;

/// Computes the default home directory.
pub fn default() -> Result<PathBuf> {
    // XXX: Support Windows, see #29.
    Ok(dirs::home_dir().ok_or(anyhow::anyhow!("unsupported platform"))?
       .join(".gnupg"))
}
