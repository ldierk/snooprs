use clap::Parser;
use snooprs::SnoopParser;

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
    let mut snoop = SnoopParser::new(&args.filename).unwrap();
    snoop.set_text_only(args.text_only);
    snoop.set_no_data(args.no_data);
    snoop.set_filter(&args.id);

    while let Some(entry) = snoop.parse_next_filtered() {
        println!("{}", entry);
    }
}
