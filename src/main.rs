use clap::Parser;
use snooprs::{SnoopConfig, SnoopParser};
use std::process;

#[derive(Parser, Debug)]
#[command(about = "Parse a pdweb.snoop trace", long_about = None)]
struct Args {
    /// file name
    filename: String,
    /// don't print data as hex
    #[arg(short, long)]
    text_only: bool,
    /// filter for thread id, can be specified multiple times
    #[arg(short, long)]
    id: Option<Vec<u64>>,
    /// don't print data
    #[arg(short, long)]
    no_data: bool,
}

fn main() {
    let args = Args::parse();
    let config = SnoopConfig::new(args.text_only, args.no_data, args.id);
    let snoop = SnoopParser::open_with_config(&args.filename, config).unwrap_or_else(|err| {
        eprintln!("Error creating snoop parser: {err}");
        process::exit(1);
    });

    for entry in snoop {
        println!("{entry}");
    }
}
