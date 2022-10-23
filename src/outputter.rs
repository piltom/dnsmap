use indicatif::{ProgressBar, ProgressStyle};
use std::{fs, io::Write, net::IpAddr};
use trust_dns_resolver::{lookup_ip::LookupIp, proto::rr::Record};

pub trait Outputter {
    fn print_headers(&mut self) -> Result<(), std::io::Error>;
    fn add_result(&mut self, lookup: LookupIp) -> Result<(), std::io::Error>;
    fn report_progress(&self, text: String);
}

pub struct FileOutput {
    file: fs::File,
    headers: bool,
    bar: ProgressBar,
}

impl FileOutput {
    pub fn new(path: &str, headers: bool, total_tries: usize) -> Result<Self, std::io::Error> {
        Ok(Self {
            file: fs::File::create(path)?,
            headers,
            bar: ProgressBar::new(total_tries as u64)
                .with_style(ProgressStyle::with_template("[{pos}/{len}] {msg}").unwrap()),
        })
    }
}

impl Outputter for FileOutput {
    fn print_headers(&mut self) -> Result<(), std::io::Error> {
        if !self.headers {
            return Ok(());
        }
        self.file.write(
            format!(
                "{0: <40} | {1: <10} | {2: <10}\n",
                "Name", "Record", "Local ip"
            )
            .as_bytes(),
        )?;

        Ok(())
    }
    fn add_result(&mut self, lookup: LookupIp) -> Result<(), std::io::Error> {
        for record in lookup.as_lookup().records() {
            self.file.write(record_to_string(record, true).as_bytes())?;
        }
        Ok(())
    }

    fn report_progress(&self, text: String) {
        self.bar.inc(1);
        self.bar.set_message(text);
    }
}

pub struct ConsoleOutput {
    headers: bool,
    bar: ProgressBar,
}

impl ConsoleOutput {
    pub fn new(headers: bool, total_tries: usize) -> Self {
        Self {
            headers,
            bar: ProgressBar::new(total_tries as u64)
                .with_style(ProgressStyle::with_template("[{pos}/{len}] {msg}").unwrap()),
        }
    }
}

impl Outputter for ConsoleOutput {
    fn print_headers(&mut self) -> Result<(), std::io::Error> {
        if !self.headers {
            return Ok(());
        }
        println!(
            "{0: <40} | {1: <10} | {2: <10}",
            "Name", "Record", "Local ip"
        );
        Ok(())
    }

    fn add_result(&mut self, lookup: LookupIp) -> Result<(), std::io::Error> {
        for record in lookup.as_lookup().records() {
            println!("{}", record_to_string(record, false));
        }
        Ok(())
    }

    fn report_progress(&self, text: String) {
        self.bar.inc(1);
        self.bar.set_message(text);
    }
}

fn record_to_string(record: &Record, add_nl: bool) -> String {
    let mut local = false;
    if let Some(rdata) = record.data() {
        local = match rdata.to_ip_addr() {
            Some(IpAddr::V4(addrv4)) => addrv4.is_private(),
            // Some(IpAddr::V6(addrv6)) => !addrv6.is_global(),  <= not stabilized in ip libs
            _ => false,
        };
    };

    if add_nl {
        format!(
            "{0: <40} | {1: <10} | {2: <10}\n",
            record.name().to_ascii(),
            record.record_type().to_string(),
            local
        )
    } else {
        format!(
            "{0: <40} | {1: <10} | {2: <10}",
            record.name().to_ascii(),
            record.record_type().to_string(),
            local
        )
    }
}
