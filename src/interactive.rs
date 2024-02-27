//! Utilities for prompting the user.

use std::{
    cell::RefCell,
    fmt,
    io,
    sync::Mutex,
};

use anyhow::Result;

use crate::{
    Config,
    status::Status,
};

pub struct Fd(Mutex<RefCell<Box<dyn io::BufRead + Send + Sync>>>);

impl<S: io::Read + Send + Sync + 'static> From<S> for Fd {
    fn from(s: S) -> Fd {
        Fd(Mutex::new(RefCell::new(Box::new(io::BufReader::new(s)))))
    }
}

impl Fd {
    /// Prompts the given question `prompt`, and reads a line from the
    /// command-fd or stdin.
    fn get_response(&self) -> Result<String> {
        let mut result = String::new();
        self.0.lock().expect("not poisoned").borrow_mut()
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
        self.status_fd.emit_or(Status::GetLine(keyword.into()),
                               &format!("{}", prompt))?;
        let response = self.command_fd.get_response()?;
        self.status_fd.emit(Status::GotIt)?;
        Ok(response)
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
        self.status_fd.emit_or(Status::GetBool(keyword.into()),
                               &format!("{} (y/N)", prompt))?;
        let a = self.command_fd.get_response()?;
        self.status_fd.emit(Status::GotIt)?;

        let a = a.to_lowercase();
        Ok(a == "y" || a == "yes")
    }
}
