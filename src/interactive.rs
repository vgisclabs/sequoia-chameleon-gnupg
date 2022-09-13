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
    pub fn prompt(&self, prompt: fmt::Arguments) -> Result<String> {
        eprint!("{} ", prompt);
        let mut result = String::new();
        self.0.lock().expect("not poisoned").borrow_mut()
            .read_line(&mut result)?;
        Ok(result.trim_end().into())
    }
}

impl Config {
    /// Prompts the given question `prompt`, and reads a line from the
    /// command-fd or stdin.
    pub fn prompt(&self, prompt: fmt::Arguments) -> Result<String> {
        self.command_fd.prompt(prompt)
    }

    /// Prompts the given yes/no question `prompt`, defaulting to no.
    #[allow(non_snake_case)]
    pub fn prompt_yN(&self, prompt: fmt::Arguments) -> Result<bool> {
        let a = self.command_fd.prompt(format_args!("{} (y/N)", prompt))?
            .to_lowercase();

        Ok(a == "y" || a == "yes")
    }
}
