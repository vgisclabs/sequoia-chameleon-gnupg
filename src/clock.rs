//! Time-abstraction that support --faked-system-time.

use std::{
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Implements a time source for all time-related operations.
///
/// Note: In this crate, you need to use `Clock::now()` instead of
/// `SystemTime::now()` in order for the faketime mechanics to work.
pub enum Clock {
    /// Use SystemTime::now.
    SystemTime,

    /// Return a fixed time.
    ///
    /// This is selected by appending a bang ("!") to the given
    /// --faked-system-time argument.
    FixedTime {
        fake_time: SystemTime,
    },

    /// Returns a time as if gpg was invoked at the given fake time.
    ///
    /// This means that time does advance.
    FakedTime {
        fake_time: SystemTime,
        startup_time: SystemTime,
    },
}

impl Default for Clock {
    fn default() -> Clock {
        Clock::SystemTime
    }
}

impl std::str::FromStr for Clock {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (t, fixed) = if s.ends_with("!") {
            (&s[..s.len()-1], true)
        } else {
            (s, false)
        };

        let fake_time = if t.chars().all(|c| c.is_numeric()) {
            UNIX_EPOCH.checked_add(Duration::new(t.parse()?, 0))
                .ok_or(anyhow::anyhow!("Duration overflows time type"))?
        } else {
            // XXX have a closer look
            crate::utils::parse_iso_date(s)?
        };

        if fixed {
            Ok(Clock::FixedTime { fake_time })
        } else {
            Ok(Clock::FakedTime { fake_time, startup_time: SystemTime::now() })
        }
    }
}

impl Clock {
    /// Returns the current (fake) time.
    pub fn now(&self) -> SystemTime {
        match self {
            Clock::SystemTime => SystemTime::now(),
            Clock::FixedTime { fake_time } => *fake_time,
            Clock::FakedTime { fake_time, startup_time } => {
                let now = SystemTime::now();
                if let Ok(since) = now.duration_since(*startup_time) {
                    fake_time.checked_add(since)
                        .expect("SystemTime not to overflow")
                } else {
                    // The clock moved backwards.  Try to do
                    // something consistent.
                    // XXX: What does GnuPG do?
                    let since = startup_time.duration_since(now)
                        .expect("one of the two operations to work");
                    fake_time.checked_sub(since)
                        .expect("SystemTime not to underflow")
                }
            },
        }
    }
}
