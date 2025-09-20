cd snooprs
cargo build
$ target/debug/snooprs < pdweb.snoop.log  > myoutput.txt
$ diff pdweb.snoop.log myoutput.txt
