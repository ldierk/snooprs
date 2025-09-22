use clap::Parser;
use snooprs::SnoopParser;
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
    let mut snoop = SnoopParser::new(&args.filename).unwrap_or_else(|err| {
        eprintln!("Error creating snoop parser: {err}");
        process::exit(1);
    });
    snoop.set_text_only(args.text_only);
    snoop.set_no_data(args.no_data);
    snoop.set_filter(&args.id);

    snoop.into_iter().for_each(|entry| println!("{entry}"));
}
