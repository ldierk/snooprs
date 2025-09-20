use chrono::{DateTime, FixedOffset};
use clap::Parser;
use regex::Regex;
use std::{
    fmt,
    io::{self, BufRead},
};

const LIMITTER: &str = "----------------------------------------";
//https://docs.rs/chrono/latest/chrono/format/strftime/index.html
//                     2025-09-14-19:30:11.018+01:00
const DATE_FORMAT: &str = "%Y-%m-%d-%H:%M:%S%.3f%:z";

/*
2025-09-14-19:28:40.550+01:00I----- thread(16) trace.pdweb.snoop.client:1 /build/isam/src/i4w/pdwebrte/webcore/amw_snoop.cpp:108:
*/
const HEADER_REGEX: &str =
    r"(?<date>\d\d\d\d-\d\d-\d\d-\d\d:\d\d:\d\d.\d\d\d\+\d\d:\d\d)I----- thread\((?<thread>\d\d)\) (?<component>.+) (?<file>.+:\d+:)(?<remainder>.*)";
/*
Thread 132916153280064; fd 261; local 10.42.0.160:35322; remote 10.43.9.26:9443
 */
const SUMMARY_REGEX: &str = r"Thread (?<thread>\d+); fd (?<fd>\d+); local (?<local>.+); remote (?<remote>.+)";

/*
0x00000   4854 5450 2f31 2e31 2033 3032 204d 6f76        HTTP/1.1.302.Mov
 */
const DATA_REGEX: &str = r"^0x[a-zA-Z0-9]{4}";
#[derive(Debug)]
struct Entry {
    header: Header,
    summary: Option<Summary>,
    action: Option<String>,
    data: Option<String>,
}

impl Entry {
    fn new(header: Header) -> Self {
        Entry {
            header,
            summary: None,
            action: None,
            data: None,
        }
    }
}

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.header.is_error() {
            write!(f, "{}\n", self.header)
        } else {
            if let Some(action) = &self.action {
                if !has_data(&action) {
                    write!(
                        f,
                        "{}\n{}\n{}\n{}\n{}\n",
                        self.header,
                        LIMITTER,
                        self.summary.as_ref().unwrap(),
                        self.action.as_ref().unwrap(),
                        LIMITTER
                    )
                } else {
                    write!(
                        f,
                        "{}\n{}\n{}\n{}\n{}\n{}\n",
                        self.header,
                        LIMITTER,
                        self.summary.as_ref().unwrap(),
                        self.action.as_ref().unwrap(),
                        self.data.as_ref().unwrap(),
                        LIMITTER
                    )
                }
            } else {
                write!(f, "{}\n", self.header)
            }
        }
    }
}

#[derive(Debug)]
enum STATE {
    Header,
    OpeningLimit,
    Summary,
    Action,
    Data,
    ClosingLimit,
}
#[derive(Debug)]
struct Header {
    date: DateTime<FixedOffset>,
    thread: u64,
    component: String,
    source_file: String,
    error_message: String,
}

impl Header {
    fn new(re: &Regex, line: &str) -> Self {
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
    // errors are one liners and not follow by data
    fn is_error(&self) -> bool {
        !self.error_message.is_empty()
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
#[derive(Debug)]
struct Summary {
    thread: u64,
    fd: u64,
    local: String,
    remote: String,
}

impl Summary {
    fn new(re: &Regex, line: &str) -> Self {
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

/*
0x3ea0   2d6c 6566 742d 7261 6469 7573 3a35 3025        -left-radius:50%
 */
const START_OF_TEXT: usize = 56;
fn snoop_to_text<'a>(line: &'a str) -> &'a str {
    &line[START_OF_TEXT..]
}

//print text wrapped at 80 chars
const WRAP_WIDTH: usize = 80;
fn format_data(data: &String) -> String {
    let mut max = WRAP_WIDTH;
    let mut min = 0;
    let len = data.len();
    if len < max {
        max = len;
    }
    let mut formatted = String::new();
    loop {
        formatted.push_str(&data[min..max]);
        formatted.push_str("\n");
        min += WRAP_WIDTH;
        max += WRAP_WIDTH;
        if max > len {
            max = len;
        }
        if min > len {
            break;
        }
    }
    formatted
}

fn has_data(line: &str) -> bool {
    line.starts_with("Sending") || line.starts_with("Receiving")
}

fn parse(s2t: bool) {
    let head_re = Regex::new(HEADER_REGEX).unwrap();
    let summary_re = Regex::new(SUMMARY_REGEX).unwrap();
    let data_re = Regex::new(DATA_REGEX).unwrap();

    let stdin = io::stdin();

    let mut state = STATE::Header;
    let mut data = String::new();
    let mut entry: Option<Entry> = None;

    //let mut header: Option<Header> = None;

    for line in stdin.lock().lines() {
        let line = line.unwrap();
        match state {
            STATE::Header => {
                if head_re.is_match(&line) {
                    let header = Header::new(&head_re, &line);
                    entry = Some(Entry::new(header));
                    if let Some(entry) = entry.as_ref() {
                        if !entry.header.is_error() {
                            state = STATE::OpeningLimit;
                        } else {
                            println!("{}", entry.header);
                        }
                    }
                }
            }
            STATE::OpeningLimit => {
                if line == LIMITTER {
                    state = STATE::Summary;
                }
            }
            STATE::Summary => {
                if summary_re.is_match(&line) {
                    let summary = Summary::new(&summary_re, &line);
                    if let Some(entry) = entry.as_mut() {
                        entry.summary = Some(summary);
                    }
                    state = STATE::Action;
                }
            }
            STATE::Action => {
                if has_data(&line) {
                    state = STATE::Data;
                } else {
                    state = STATE::ClosingLimit;
                }
                if let Some(entry) = entry.as_mut() {
                    entry.action = Some(line);
                }
            }
            STATE::Data => {
                if data_re.is_match(&line) {
                    if s2t {
                        let text = snoop_to_text(&line);
                        data.push_str(text);
                    } else {
                        data.push_str(&line);
                        data.push_str("\n");
                    }
                //an empty line signals the end of data
                } else if line.is_empty() {
                    if s2t {
                        if let Some(entry) = entry.as_mut() {
                            entry.data = Some(format_data(&data));
                        }
                    } else {
                        if let Some(entry) = entry.as_mut() {
                            entry.data = Some(data.to_string());
                        }
                    }
                    data.clear();
                    //println!(); //the empty line we're just handling
                    state = STATE::ClosingLimit;
                }
            }
            STATE::ClosingLimit => {
                if line == LIMITTER {
                    if let Some(entry) = entry.as_ref() {
                        println!("{}", entry);
                    }
                    state = STATE::Header;
                }
            }
        }
    }
}

#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct Args {
    /// snoop to text
    #[arg(short, long, action)]
    text: bool,
}

fn main() {
    let args = Args::parse();
    parse(args.text);
}
