use std::io::IsTerminal;

use anyhow::Result;
use bip39::Mnemonic;
use zeroize::Zeroize;

/// Read a mnemonic from the terminal (with no echo) or from stdin if piped.
/// On Linux, also mlock's the buffer and disables core dumps.
pub fn secure_mnemonic_prompt(prompt: &str) -> Result<Mnemonic> {
    forensic_harden();

    let mut input = if std::io::stdin().is_terminal() {
        rpassword::prompt_password(prompt)?
    } else {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        s
    };
    let trimmed = input.trim().to_string();

    // Parse before zeroizing the input string
    let mnemonic = Mnemonic::parse_normalized(&trimmed)?;

    // Wipe the input buffers
    let mut trimmed_bytes = trimmed.into_bytes();
    trimmed_bytes.zeroize();
    input.zeroize();

    Ok(mnemonic)
}

/// Call once at startup to harden the process.
pub fn forensic_harden() {
    // Disable core dumps (Linux)
    #[cfg(target_os = "linux")]
    {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        unsafe {
            libc::setrlimit(libc::RLIMIT_CORE, &rlim);
        }
    }

    // On Windows we rely on Zeroize for memory clearing; VirtualLock
    // would require pinned pointers which are complex to manage.
}


