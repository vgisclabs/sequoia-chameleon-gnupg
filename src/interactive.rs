//! Utilities for prompting the user.

use std::{
    cell::RefCell,
    fmt,
    io,
    sync::Mutex,
};

use anyhow::Result;

use sequoia_openpgp::{
    crypto::Password,
};

use crate::{
    Config,
    status::Status,
};

pub struct Fd {
    handle: Mutex<RefCell<Box<dyn io::BufRead + Send + Sync>>>,
    interactive: bool,
}

impl<S: io::Read + Send + Sync + 'static> From<S> for Fd {
    fn from(s: S) -> Fd {
        Fd {
            handle: Mutex::new(RefCell::new(Box::new(io::BufReader::new(s)))),
            interactive: false,
        }
    }
}

impl Fd {
    /// Configures the Chameleon for interactive use.
    pub fn interactive() -> Self {
        let mut fd: Self = io::stdin().into();
        fd.interactive = true;
        fd
    }

    /// Whether the Chameleon is configured for interactive use.
    pub fn is_interactive(&self) -> bool {
        self.interactive
    }

    /// Prompts the given question `prompt`, and reads a line from the
    /// command-fd or stdin.
    fn get_response(&self) -> Result<String> {
        let mut result = String::new();
        self.handle.lock().expect("not poisoned").borrow_mut()
            .read_line(&mut result)?;
        Ok(result.trim_end().into())
    }
}

impl Config<'_> {
    /// Prompts the given question.
    ///
    /// Prompts the given question `keyword` (when reading via
    /// command-fd) or `prompt` (when reading via `stdin`), and reads
    /// a line from the command-fd or stdin, as appropriate.
    pub fn prompt(&self, keyword: &str, prompt: fmt::Arguments)
        -> Result<String>
    {
        if self.command_fd.interactive && self.batch {
            return Err(anyhow::anyhow!(
                "Sorry, we are in batchmode - can't get input"));
        }

        self.status_fd.emit_or_prompt(
            Status::GetLine(keyword.into()),
            &format!("{}", prompt))?;
        let response = self.command_fd.get_response()?;
        self.status_fd.emit(Status::GotIt)?;
        Ok(response)
    }

    /// Prompts for a password.
    ///
    /// Prompts the given question `keyword` (when reading via
    /// command-fd) or `prompt` (when reading via `stdin`), and reads
    /// a line from the command-fd or stdin, as appropriate.
    pub fn prompt_password(&self) -> Result<Password>
    {
        if self.command_fd.interactive && self.batch {
            return Err(anyhow::anyhow!(
                "Sorry, we are in batchmode - can't get input"));
        }

        if self.command_fd.interactive {
            Ok(rpassword::prompt_password("Enter passphrase: ")?.into())
        } else {
            self.status_fd.emit(Status::GetHidden("passphrase.enter".into()))?;
            let mut password = String::new();
            self.command_fd.handle.lock().expect("not poisoned").borrow_mut()
                .read_line(&mut password)?;
            if password.ends_with("\n") {
                password.pop();
            }
            let password = password.into();
            self.status_fd.emit(Status::GotIt)?;
            Ok(password)
        }
    }

    /// Prompts the given yes/no question, defaulting to no.
    ///
    /// Prompts the given yes/no question `keyword` (when reading via
    /// command-fd) or `prompt` (when reading via `stdin`), and reads
    /// a line from the command-fd or stdin, as appropriate.  Defaults
    /// to `no`.
    #[allow(non_snake_case)]
    pub fn prompt_yN(&self, keyword: &str, prompt: fmt::Arguments)
        -> Result<bool>
    {
        if self.command_fd.interactive && self.batch {
            return Err(anyhow::anyhow!(
                "Sorry, we are in batchmode - can't get input"));
        }

        self.status_fd.emit_or_prompt(
            Status::GetBool(keyword.into()),
            &format!("{} (y/N)", prompt))?;
        let a = self.command_fd.get_response()?;
        self.status_fd.emit(Status::GotIt)?;

        let a = a.to_lowercase();
        Ok(a == "y" || a == "yes")
    }

    /// Prompts the given yes/no question, defaulting to yes.
    ///
    /// Prompts the given yes/no question `keyword` (when reading via
    /// command-fd) or `prompt` (when reading via `stdin`), and reads
    /// a line from the command-fd or stdin, as appropriate.  Defaults
    /// to `yes`.
    #[allow(non_snake_case)]
    pub fn prompt_Yn(&self, keyword: &str, prompt: fmt::Arguments)
        -> Result<bool>
    {
        if self.command_fd.interactive && self.batch {
            return Err(anyhow::anyhow!(
                "Sorry, we are in batchmode - can't get input"));
        }

        self.status_fd.emit_or_prompt(
            Status::GetBool(keyword.into()),
            &format!("{} (Y/n)", prompt))?;
        let a = self.command_fd.get_response()?;
        self.status_fd.emit(Status::GotIt)?;

        let a = a.to_lowercase();
        Ok(! (a == "n" || a == "no"))
    }
}
