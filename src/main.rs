use chrono::{DateTime, FixedOffset};
use clap::Parser;
use regex::Regex;
use std::{
    fmt::{self},
    io::{self, BufRead, Write},
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
enum STATE {
    Header,
    OpeningLimit,
    Summary,
    Action,
    Data,
    ClosingLimit,
}

#[derive(Debug)]
struct ErrorEntry {
    header: Header,
}
#[derive(Debug)]
struct ActionEntry {
    header: Header,
    summary: Summary,
    action: Action,
}
#[derive(Debug)]
struct DataEntry {
    header: Header,
    summary: Summary,
    action: Action,
    data: String,
}
#[derive(Debug)]
enum Entry {
    ErrorEntry(ErrorEntry),
    ActionEntry(ActionEntry),
    DataEntry(DataEntry),
}

impl Entry {
    fn new_error_entry(header: Header) -> Self {
        Entry::ErrorEntry(ErrorEntry { header })
    }

    fn new_action_entry(header: Header, summary: Summary, action: Action) -> Self {
        Entry::ActionEntry(ActionEntry { header, summary, action })
    }

    fn new_data_entry(header: Header, summary: Summary, action: Action, data: String) -> Self {
        Entry::DataEntry(DataEntry { header, summary, action, data })
    }

    fn get_id(&self) -> u64 {
        match self {
            Entry::ErrorEntry(entry) => entry.header.thread,
            Entry::ActionEntry(entry) => entry.header.thread,
            Entry::DataEntry(entry) => entry.header.thread,
        }
    }
}

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Entry::ErrorEntry(entry) => write!(f, "{}", entry.header),
            Entry::ActionEntry(entry) => write!(f, "{}\n{}\n{}\n{}\n{}\n", entry.header, LIMITTER, entry.summary, entry.action, LIMITTER),
            Entry::DataEntry(entry) => write!(
                f,
                "{}\n{}\n{}\n{}\n{}\n{}\n",
                entry.header, LIMITTER, entry.summary, entry.action, entry.data, LIMITTER
            ),
        }
    }
}

#[derive(Debug, Clone)]
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
    // errors have a message after the source_file but nothing else is following
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
#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
struct Action {
    action: String,
}
impl Action {
    fn has_data(&self) -> bool {
        self.action.starts_with("Sending") || self.action.starts_with("Receiving")
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.action)
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

fn construct_entry(header: &Option<Header>, summary: &Option<Summary>, action: &Option<Action>, data: &String) -> Entry {
    let header = header.clone().unwrap();
    if header.is_error() {
        Entry::new_error_entry(header)
    } else {
        let summary = summary.clone().unwrap();
        let action = action.clone().unwrap();
        if action.has_data() {
            let data = data.clone();
            Entry::new_data_entry(header, summary, action, data)
        } else {
            Entry::new_action_entry(header, summary, action)
        }
    }
}

fn filter_entry(entry: &Entry, ids: &Option<Vec<u64>>) {
    match ids {
        //no filter given, print
        None => {
            let _ = writeln!(std::io::stdout(), "{}", entry);
        }
        Some(ids) => {
            if ids.contains(&entry.get_id()) {
                let _ = writeln!(std::io::stdout(), "{}", entry);
            }
        }
    }
}

fn parse(s2t: bool, ids: &Option<Vec<u64>>, no_data: bool) {
    let head_re = Regex::new(HEADER_REGEX).unwrap();
    let summary_re = Regex::new(SUMMARY_REGEX).unwrap();
    let data_re = Regex::new(DATA_REGEX).unwrap();

    let stdin = io::stdin();

    let mut state = STATE::Header;
    //the parts of an entry
    let mut header: Option<Header> = None;
    let mut summary: Option<Summary> = None;
    let mut action: Option<Action> = None;
    let mut data: String = String::new();

    for line in stdin.lock().lines() {
        let line = line.unwrap();
        match state {
            STATE::Header => {
                if head_re.is_match(&line) {
                    header = Some(Header::new(&head_re, &line));
                    if !header.as_ref().unwrap().is_error() {
                        state = STATE::OpeningLimit;
                    } else {
                        //if is_error we have a one-liner and we are done
                        let entry = construct_entry(&header, &summary, &action, &data);
                        filter_entry(&entry, &ids);
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
                    summary = Some(Summary::new(&summary_re, &line));
                    state = STATE::Action;
                }
            }
            STATE::Action => {
                action = Some(Action { action: line });
                if action.as_ref().unwrap().has_data() {
                    state = STATE::Data;
                } else {
                    state = STATE::ClosingLimit;
                }
            }
            STATE::Data => {
                if !no_data && data_re.is_match(&line) {
                    if s2t {
                        let text = snoop_to_text(&line);
                        data.push_str(text);
                    } else {
                        data.push_str(&line);
                        data.push_str("\n");
                    }
                } else if line.is_empty() {
                    //an empty line signals the end of data
                    state = STATE::ClosingLimit;
                }
            }
            STATE::ClosingLimit => {
                if line == LIMITTER {
                    if !no_data && s2t {
                        data = format_data(&data);
                    }
                    let entry = construct_entry(&header, &summary, &action, &data);
                    filter_entry(&entry, &ids);
                    data.clear();
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
    /// filter for thread id, can be specified multiple times
    #[arg(short, long)]
    id: Option<Vec<u64>>,
    /// don't print data
    #[arg(short, long, action)]
    no_data: bool,
}

fn main() {
    let args = Args::parse();
    parse(args.text, &args.id, args.no_data);
}
