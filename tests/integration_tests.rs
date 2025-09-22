use std::{
    fs::File,
    io::{BufReader, Read},
};

use snooprs::SnoopParser;

#[test]
fn input_eq_output() {
    let filename = "pdweb.snoop.log";
    let mut input = BufReader::new(File::open(filename).unwrap());
    let mut buf = String::new();
    match input.read_to_string(&mut buf) {
        Ok(_) => {
            let mut snoop = SnoopParser::new(&filename).unwrap();
            let mut buf2 = String::new();
            while let Some(entry) = snoop.parse_next_filtered() {
                buf2.push_str(&format!("{}\n", entry));
            }
            assert_eq!(buf, buf2);
        }
        Err(e) => panic!("{}", e),
    }
}
