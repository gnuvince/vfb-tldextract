use flate2::read::GzDecoder;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;
use structopt::StructOpt;

const PROG: &str = env!("CARGO_BIN_NAME");

#[derive(StructOpt)]
struct Cli {
    #[structopt(parse(from_os_str))]
    tld_data_file: PathBuf,

    #[structopt(parse(from_os_str))]
    input_file: PathBuf,

    #[structopt(parse(from_os_str))]
    rejected_file: PathBuf,
}

#[derive(Deserialize)]
struct RdnsRecord {
    name: String,
    value: String,
}

fn parse_tld_file(filename: &PathBuf) -> anyhow::Result<HashSet<String>> {
    let rdr = BufReader::new(File::open(filename)?);
    let mut set: HashSet<String> = HashSet::with_capacity(4096);
    for line in rdr.lines() {
        let line = line?;
        if line.trim().is_empty() || line.starts_with("//") {
            continue;
        }
        set.insert(line);
    }
    return Ok(set);
}

fn rfind_from(s: &str, c: char, offset: usize) -> Option<usize> {
    (&s[..offset]).rfind(c)
}

fn domain_for<'a, 'b>(host: &'a str, tld_set: &'b HashSet<String>) -> Option<&'a str> {
    // The current longest TLD suffix extends from frontier to the end of `host`.
    let mut frontier: usize = host.len();

    while let Some(idx) = rfind_from(host, '.', frontier) {
        let s = &host[idx + 1..];
        if !tld_set.contains(s) {
            break;
        }
        frontier = idx;
    }

    if frontier == host.len() {
        return None;
    }

    // host[frontier..] is the tld, now let's find the domain.
    let start = match rfind_from(host, '.', frontier) {
        Some(idx) => idx + 1,
        None => 0,
    };
    return Some(&host[start..frontier]);
}

fn main() -> anyhow::Result<()> {
    let args = Cli::from_args();
    let file = File::open(&args.input_file)?;
    let mut rdr = BufReader::new(GzDecoder::new(file));
    let mut rejected = BufWriter::new(File::create(&args.rejected_file)?);
    let tld_set = parse_tld_file(&args.tld_data_file)?;

    let stdout = io::stdout();
    let stdout = stdout.lock();
    let mut stdout = BufWriter::new(stdout);

    // Use read_line() so that we can re-use the same buffer;
    // the .lines() iterator allocates a new string for every
    // line.
    let mut line = String::with_capacity(4096);
    let mut num_lines: u64 = 0;
    let mut num_rejected: u64 = 0;

    let t0 = std::time::Instant::now();
    loop {
        line.clear();
        let n = rdr.read_line(&mut line)?;
        if n == 0 {
            break;
        }

        // If the record contains unicode characters, write it to another file
        // to be processed later.
        if line.contains(r"\u") {
            rejected.write(line.as_bytes())?;
            num_rejected += 1;
            continue;
        }

        num_lines += 1;

        let record: RdnsRecord = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(_) => {
                eprintln!("{}: cannot deserialize this line: {:?}", PROG, line);
                continue;
            }
        };
        if let Some(domain) = domain_for(&record.value, &tld_set) {
            let ip: u32 = u32::from(Ipv4Addr::from_str(&record.name)?);
            writeln!(stdout, "{},{}", ip, domain)?;
        }
    }
    eprintln!(
        "{}: processed {} lines ({} rejected) in {:?}",
        PROG,
        num_lines,
        num_rejected,
        t0.elapsed()
    );
    return Ok(());
}
