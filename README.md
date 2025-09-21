```
cd snooprs
cargo build
$ target/debug/snooprs < pdweb.snoop.log  > myoutput.txt
$ diff pdweb.snoop.log myoutput.txt
$ target/debug/snooprs -h
$ target/debug/snooprs -t < pdweb.snoop.log
$ target/debug/snooprs -i 21 -i 10 < pdweb.snoop.log
$ target/debug/snooprs -t -i 23 < pdweb.snoop.log
$ target/debug/snooprs -n < pdweb.snoop.log
```