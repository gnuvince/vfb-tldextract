use flate2::read::GzDecoder;
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
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

#[derive(Debug)]
struct RdnsInfoPositions {
    name: (usize, usize),
    value: (usize, usize),
}

#[derive(Debug)]
struct Parser<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn is_white(c: u8) -> bool {
        let b0 = c == b' ';
        let b1 = c == b'\t';
        let b2 = c == b'\n';
        let b3 = c == b'\r';
        return b0 | b1 | b2 | b3;
    }

    fn skip_white(&mut self) {
        while let Some(b) = self.buf.get(self.pos) {
            if Self::is_white(*b) {
                self.pos += 1;
            } else {
                return;
            }
        }
    }

    fn expect(&mut self, c: u8) -> Option<()> {
        self.skip_white();
        if self.buf[self.pos] == c {
            self.pos += 1;
            return Some(());
        } else {
            return None;
        }
    }

    fn peek(&self) -> u8 {
        return *self.buf.get(self.pos).unwrap_or(&0);
    }

    fn string(&mut self) -> Option<(usize, usize)> {
        self.expect(b'"')?;
        let start = self.pos;
        while self.peek() != b'"' {
            self.pos += 1;
        }
        let end = self.pos;
        self.expect(b'"')?;
        return Some((start, end));
    }

    fn parse(&mut self) -> Option<RdnsInfoPositions> {
        self.expect(b'{')?;
        self.skip_white();

        let _ts_key = self.string()?;
        self.expect(b':')?;
        let _ts_val = self.string()?;
        self.expect(b',')?;

        let name_key = self.string()?;
        self.expect(b':')?;
        let name_val = self.string()?;
        self.expect(b',')?;

        let _ptr_key = self.string()?;
        self.expect(b':')?;
        let _ptr_val = self.string()?;
        self.expect(b',')?;

        let value_key = self.string()?;
        self.expect(b':')?;
        let value_val = self.string()?;
        self.expect(b'}')?;

        // assert_eq!(&self.buf[value_key.0..value_key.1], b"value");
        // assert_eq!(&self.buf[name_key.0..name_key.1], b"name");

        return Some(RdnsInfoPositions {
            name: name_val,
            value: value_val,
        });
    }
}

fn buf_to_str(buf: &[u8], (start, end): (usize, usize)) -> &str {
    return unsafe { std::str::from_utf8_unchecked(&buf[start..end]) };
}

fn ipv4_to_u32(s: &[u8]) -> u32 {
    let mut ip: u32 = 0;
    let mut octet: u32 = 0;
    let mut curr_octet: usize = 0;
    let shifts: [u32; 4] = [24, 16, 8, 0];
    for b in s {
        if *b == b'.' {
            let shift = shifts[curr_octet];
            ip += octet << shift;
            curr_octet += 1;
            octet = 0;
        } else {
            octet = octet * 10 + (*b - b'0') as u32;
        }
    }
    let shift = shifts[curr_octet];
    ip += octet << shift;
    return ip;
}

// fn main() -> anyhow::Result<()> {
//     let mut p = Parser {
//         buf: br#"{"timestamp": "1627467007", "name": "1.120.175.74", "type": "cname", "value": "cpe-1-120-175-74.4cbp-r-037.cha.qld.bigpond.net.au"}"#,
//         pos: 0,
//     };
//     println!("{:?}", p);
//     let x = p.parse();
//     println!("{:?}", p);
//     println!("{:?}", x);
//     let x = x.unwrap();
//     println!("{:?}", buf_to_str(&p.buf, x.name)?);
//     println!("{:?}", buf_to_str(&p.buf, x.value)?);
//     return Ok(());
// }

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

        let mut parser = Parser {
            buf: line.as_bytes(),
            pos: 0,
        };
        let rdns = match parser.parse() {
            Some(rdns) => rdns,
            None => {
                eprintln!("{}: cannot deserialize this line: {:?}", PROG, line);
                continue;
            }
        };

        let domain = buf_to_str(&parser.buf, rdns.value);

        if let Some(domain) = domain_for(domain, &tld_set) {
            let ip: u32 = ipv4_to_u32(&parser.buf[rdns.name.0..rdns.name.1]);
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

// fn main() {
//     println!("{}", ipv4_to_u32(b"192.168.32.1"));
//     println!("{}", u32::from(Ipv4Addr::from_str("192.168.32.1").unwrap()));
// }
