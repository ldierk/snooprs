mod fields;
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::{fmt, io::Lines};

use fields::{Action, Header, Summary};

const LIMITTER: &str = "----------------------------------------";

//2025-09-14-19:28:40.550+01:00I----- thread(16) trace.pdweb.snoop.client:1 /build/isam/src/i4w/pdwebrte/webcore/amw_snoop.cpp:108:
const HEADER_REGEX: &str =
    r"(?<date>\d\d\d\d-\d\d-\d\d-\d\d:\d\d:\d\d.\d\d\d\+\d\d:\d\d)I----- thread\((?<thread>\d\d)\) (?<component>.+) (?<file>.+:\d+:)(?<remainder>.*)";

//Thread 132916153280064; fd 261; local 10.42.0.160:35322; remote 10.43.9.26:9443

const SUMMARY_REGEX: &str = r"Thread (?<thread>\d+); fd (?<fd>\d+); local (?<local>.+); remote (?<remote>.+)";

//0x00000   4854 5450 2f31 2e31 2033 3032 204d 6f76        HTTP/1.1.302.Mov
const DATA_REGEX: &str = r"^0x[a-zA-Z0-9]{4}";

enum STATE {
    Header,
    OpeningLimit,
    Summary,
    Action,
    Data,
    ClosingLimit,
}
#[derive(Clone)]
pub struct ErrorEntry {
    header: Header,
}
#[derive(Clone)]
pub struct ActionEntry {
    header: Header,
    summary: Summary,
    action: Action,
}
#[derive(Clone)]
pub struct DataEntry {
    header: Header,
    summary: Summary,
    action: Action,
    data: String,
}
#[derive(Clone)]
pub enum Entry {
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

    fn new_data_entry(header: Header, summary: Summary, action: Action, data: &str) -> Self {
        Entry::DataEntry(DataEntry {
            header,
            summary,
            action,
            data: data.to_owned(),
        })
    }

    fn new(header: &Option<Header>, summary: &Option<Summary>, action: &Option<Action>, data: &str) -> Entry {
        let header = header.clone().unwrap();
        if header.is_error() {
            Entry::new_error_entry(header)
        } else {
            let summary = summary.clone().unwrap();
            let action = action.clone().unwrap();
            if action.has_data() {
                Entry::new_data_entry(header, summary, action, data)
            } else {
                Entry::new_action_entry(header, summary, action)
            }
        }
    }

    pub fn get_id(&self) -> u64 {
        match self {
            Entry::ErrorEntry(entry) => entry.header.get_thread(),
            Entry::ActionEntry(entry) => entry.header.get_thread(),
            Entry::DataEntry(entry) => entry.header.get_thread(),
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
/*
0x3ea0   2d6c 6566 742d 7261 6469 7573 3a35 3025        -left-radius:50%
 */
const START_OF_TEXT: usize = 56;
fn snoop_to_text(line: &str) -> &str {
    &line[START_OF_TEXT..]
}
#[derive(Debug)]
pub struct SnoopError {
    message: String,
}
impl fmt::Display for SnoopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl<E: std::error::Error> From<E> for SnoopError {
    fn from(e: E) -> Self {
        SnoopError { message: e.to_string() }
    }
}

pub struct SnoopParser {
    wrap_width: usize,
    head_re: Regex,
    summary_re: Regex,
    data_re: Regex,
    input: Lines<BufReader<File>>,
    no_data: bool,
    text_only: bool,
    filter: Option<Vec<u64>>,
}

impl SnoopParser {
    pub fn new(filename: &str) -> Result<SnoopParser, SnoopError> {
        let head_re = Regex::new(HEADER_REGEX)?;
        let summary_re = Regex::new(SUMMARY_REGEX)?;
        let data_re = Regex::new(DATA_REGEX)?;

        let input = BufReader::new(File::open(filename)?).lines();
        Ok(SnoopParser {
            wrap_width: 80,
            head_re,
            summary_re,
            data_re,
            input,
            no_data: false,
            text_only: false,
            filter: None,
        })
    }

    pub fn new_with_options(filename: &str, text_only: bool, no_data: bool) -> Result<SnoopParser, SnoopError> {
        match SnoopParser::new(filename) {
            Ok(other) => Ok(SnoopParser { text_only, no_data, ..other }),
            Err(e) => Err(e),
        }
    }

    pub fn set_text_only(&mut self, text_only: bool) {
        self.text_only = text_only;
    }

    pub fn set_no_data(&mut self, no_data: bool) {
        self.no_data = no_data;
    }

    pub fn set_filter(&mut self, filter: &Option<Vec<u64>>) {
        self.filter = filter.clone();
    }
    pub fn parse_next_filtered(&mut self) -> Option<Entry> {
        while let Some(e) = self.parse_next().as_ref() {
            if let Some(filter) = &self.filter {
                if filter.contains(&e.get_id()) {
                    return Some(e.clone());
                }
            } else {
                return Some(e.clone());
            }
        }
        None
    }
    pub fn parse_next(&mut self) -> Option<Entry> {
        let mut state = STATE::Header;
        //the parts of an entry
        let mut header: Option<Header> = None;
        let mut summary: Option<Summary> = None;
        let mut action: Option<Action> = None;
        let mut data: String = String::new();

        while let Some(line) = self.input.next() {
            let line = line.unwrap();

            match state {
                STATE::Header => {
                    if self.head_re.is_match(&line) {
                        header = Some(Header::new(&self.head_re, &line));
                        if !header.as_ref().unwrap().is_error() {
                            state = STATE::OpeningLimit;
                        } else {
                            //if is_error we have a one-liner and we are done
                            let entry = Entry::new(&header, &summary, &action, &data);
                            return Some(entry);
                        }
                    }
                }
                STATE::OpeningLimit => {
                    if line == LIMITTER {
                        state = STATE::Summary;
                    }
                }
                STATE::Summary => {
                    if self.summary_re.is_match(&line) {
                        summary = Some(Summary::new(&self.summary_re, &line));
                        state = STATE::Action;
                    }
                }
                STATE::Action => {
                    action = Some(Action::new(&line));
                    if action.as_ref().unwrap().has_data() {
                        state = STATE::Data;
                    } else {
                        state = STATE::ClosingLimit;
                    }
                }
                STATE::Data => {
                    if !self.no_data && self.data_re.is_match(&line) {
                        if self.text_only {
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
                        if !self.no_data && self.text_only {
                            data = self.format_data(&data);
                        }
                        let entry = Entry::new(&header, &summary, &action, &data);
                        data.clear();
                        return Some(entry);
                    }
                }
            }
        }
        None
    }

    //print text wrapped at 80 chars
    fn format_data(&self, data: &str) -> String {
        let mut max = self.wrap_width;
        let mut min = 0;
        let len = data.len();
        if len < max {
            max = len;
        }
        let mut formatted = String::new();
        loop {
            formatted.push_str(&data[min..max]);
            formatted.push_str("\n");
            min += self.wrap_width;
            max += self.wrap_width;
            if max > len {
                max = len;
            }
            if min > len {
                break;
            }
        }
        formatted
    }
}
