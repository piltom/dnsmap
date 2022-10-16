use clap::Parser;
use trust_dns_resolver::config::{LookupIpStrategy, NameServerConfig, Protocol};

use std::error::Error;
use std::sync::{Arc, Mutex};
use std::fs;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    AsyncResolver,
};

mod subdomains;
mod outputter;
use outputter::{FileOutput, ConsoleOutput, Outputter};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Domain to scan
    #[arg()]
    domain: String,

    /// Optional list of words file to use as a prefix (uses default if not present)
    #[arg(short, long)]
    word_list: Option<String>,

    /// Output to a file instead of stdout
    #[arg(short, long)]
    output: Option<String>,

    /// Lookup ip strategy.
    ///
    ///  both : Both ipv6 and ipv4 records
    ///
    ///  6    : Only ipv6 records
    ///
    ///  4    : Only ipv4 records
    ///
    ///  6f   : ipv6 first, then ipv4
    ///
    ///  4f   : ipv4 first, then ipv6
    ///
    #[arg(short, long)]
    strategy: Option<String>,

    /// Dns server to use for looking up.
    ///
    /// Value can be an ip address or 'google', 'cloudflare' or 'quad9'
    #[arg(short, long)]
    dns_server: Option<String>,

    /// Print table headers
    #[arg(short)]
    table_headers: bool,

    /// Number of parallel requests
    #[arg(short)]
    j: Option<usize>,
}

fn get_strategy(strategy: &str) -> LookupIpStrategy {
    match strategy {
        "both" => LookupIpStrategy::Ipv4AndIpv6,
        "6" => LookupIpStrategy::Ipv6Only,
        "4" => LookupIpStrategy::Ipv4Only,
        "6f" => LookupIpStrategy::Ipv6thenIpv4,
        "4f" => LookupIpStrategy::Ipv4thenIpv6,
        _ => LookupIpStrategy::Ipv4AndIpv6,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let j = args.j.unwrap_or(1);
    assert!(j > 0);

    let out: Arc<Mutex<Box<dyn Outputter + Send>>> = match &args.output {
        Some(filename) => Arc::new(Mutex::new(Box::new(FileOutput::new(filename, args.table_headers)?))),
        None => Arc::new(Mutex::new(Box::new(ConsoleOutput::new(args.table_headers)))),
    };


    let mut opts = ResolverOpts::default();

    if let Some(strategy) = args.strategy {
        opts.ip_strategy = get_strategy(&strategy);
    }

    let config = match args.dns_server {
        Some(dns) => match dns.as_str() {
            "google" => ResolverConfig::google(),
            "cloudflare" => ResolverConfig::cloudflare(),
            "quad9" => ResolverConfig::quad9(),
            _ => {
                let mut config = ResolverConfig::new();
                config.add_name_server(NameServerConfig {
                    socket_addr: dns.parse()?,
                    protocol: Protocol::Udp,
                    tls_dns_name: None,
                    trust_nx_responses: false,
                    bind_addr: None,
                });
                config
            }
        },
        None => ResolverConfig::google(),
    };

    let resolver = AsyncResolver::tokio(config, opts)?;

    let file;
    let file_lines;
    let custom_list: Option<_> = match args.word_list {
        Some(path) => {
            file = fs::read_to_string(path)?;
            file_lines = file.lines().collect::<Vec<&str>>();
            Some(file_lines.iter())
        },
        _ => None
    };

    out.lock().unwrap().print_headers()?;

    tokio_scoped::scope(|scope| {

        let word_iter = match custom_list {
            Some(mylist) => mylist,
            _ => subdomains::SUBS.iter()
        };

        for word in word_iter {
            while Arc::strong_count(&out) > j {}

            let domain = format!("{}.{}", word, args.domain);
            let out_arc = Arc::clone(&out);
            let task = resolver.lookup_ip(domain);

            scope.spawn(async move {
                if let Ok(lookup) = task.await {
                    out_arc.lock().unwrap().add_result(lookup).unwrap();
                }
            });
        }
    });

    Ok(())
}
