use indicatif::{ProgressBar, ProgressStyle};
use std::{fs, io::Write};
use trust_dns_resolver::lookup_ip::LookupIp;

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
        self.file.write("Name\t\t\tRecord Type\n".as_bytes())?;

        Ok(())
    }
    fn add_result(&mut self, lookup: LookupIp) -> Result<(), std::io::Error> {
        for record in lookup.as_lookup().records() {
            self.file.write(
                format!(
                    "{}\t\t\t{}\n",
                    record.name().to_ascii(),
                    record.record_type()
                )
                .as_bytes(),
            )?;
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
        println!("Name\t\t\tRecord Type");
        Ok(())
    }

    fn add_result(&mut self, lookup: LookupIp) -> Result<(), std::io::Error> {
        for record in lookup.as_lookup().records() {
            println!(
                "{}\t\t\t{}", record.name().to_ascii(), record.record_type()
            );
        }
        Ok(())
    }

    fn report_progress(&self, text: String) {
        self.bar.inc(1);
        self.bar.set_message(text);
    }
}
