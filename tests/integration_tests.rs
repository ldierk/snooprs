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
            let snoop = SnoopParser::open(&filename).unwrap();
            let mut buf2 = String::new();
            for entry in snoop {
                buf2.push_str(&entry.to_string());
                buf2.push_str("\n");
            }
            assert_eq!(buf, buf2);
        }
        Err(e) => panic!("{}", e),
    }
}
#[test]
fn filtered_input_eq_output() {
    let filename1 = "pdweb.snoop.log";
    let filename2 = "pdweb.snoop.log.10";

    let mut input1 = BufReader::new(File::open(filename1).unwrap());
    let mut input2 = BufReader::new(File::open(filename2).unwrap());
    let mut buf_file1 = String::new();
    let mut buf_file2 = String::new();
    input1.read_to_string(&mut buf_file1).unwrap();
    input2.read_to_string(&mut buf_file2).unwrap();

    let filter: Vec<u64> = vec![10];
    let mut snoop = SnoopParser::open(&filename1).unwrap();
    snoop.set_filter(&Some(filter));

    let mut buf_output = String::new();
    for entry in snoop {
        buf_output.push_str(&entry.to_string());
        buf_output.push_str("\n");
    }
    assert_eq!(buf_file2, buf_output);
}
