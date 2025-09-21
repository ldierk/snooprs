use chrono::{DateTime, FixedOffset};
use regex::Regex;
use std::fmt;

//https://docs.rs/chrono/latest/chrono/format/strftime/index.html
//                     2025-09-14-19:30:11.018+01:00
const DATE_FORMAT: &str = "%Y-%m-%d-%H:%M:%S%.3f%:z";

#[derive(Clone)]
pub struct Header {
    date: DateTime<FixedOffset>,
    thread: u64,
    component: String,
    source_file: String,
    error_message: String,
}

impl Header {
    pub fn new(re: &Regex, line: &str) -> Self {
        let caps = re.captures(line).unwrap();
        let date = &caps["date"];
        let date = DateTime::parse_from_str(date, DATE_FORMAT).unwrap();
        let thread = &caps["thread"];
        let thread = thread.parse::<u64>().unwrap();
        let component = (&caps["component"]).to_string();
        let source_file = (&caps["file"]).to_string();
        let error_message = (&caps["remainder"]).trim().to_string();
        Header {
            date,
            thread,
            component,
            source_file,
            error_message,
        }
    }
    // errors have a message after the source_file but nothing else is following
    pub fn is_error(&self) -> bool {
        !self.error_message.is_empty()
    }

    pub fn get_thread(&self) -> u64 {
        self.thread
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let date = self.date.format(DATE_FORMAT);
        write!(
            f,
            "{}I----- thread({}) {} {} {}",
            date, self.thread, self.component, self.source_file, self.error_message
        )
    }
}
#[derive(Clone)]
pub struct Summary {
    thread: u64,
    fd: u64,
    local: String,
    remote: String,
}

impl Summary {
    pub fn new(re: &Regex, line: &str) -> Self {
        let caps = re.captures(line).unwrap();
        let thread = &caps["thread"];
        let thread = thread.parse::<u64>().unwrap();
        let fd = &caps["fd"];
        let fd = fd.parse::<u64>().unwrap();
        let local = (&caps["local"]).to_string();
        let remote = (&caps["remote"]).to_string();
        Summary { thread, fd, local, remote }
    }
}

impl fmt::Display for Summary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Thread {}; fd {}; local {}; remote {}", self.thread, self.fd, self.local, self.remote)
    }
}

#[derive(Clone)]
pub struct Action {
    action: String,
}
impl Action {
    pub fn new(action: &str) -> Self {
        Action { action: action.to_owned() }
    }
    pub fn has_data(&self) -> bool {
        self.action.starts_with("Sending") || self.action.starts_with("Receiving")
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.action)
    }
}
