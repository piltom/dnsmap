Tool for brute-forcing/scanning for existing subdomains in a domain. Based on dnsmap c application.

Can query configurable DNS servers, execute requests paralelly or not (see `-j`) and filter out by ip type. More features on the way.

# Usage

```
Usage: dnsmap-rs [OPTIONS] <DOMAIN>

Arguments:
  <DOMAIN>
          Domain to scan

Options:
  -w, --word-list <WORD_LIST>
          Optional list of words file to use as a prefix (uses default if not present)

  -o, --output <OUTPUT>
          Output to a file instead of stdout

  -s, --strategy <STRATEGY>
          Lookup ip strategy.

          both : Both ipv6 and ipv4 records

          6    : Only ipv6 records

          4    : Only ipv4 records

          6f   : ipv6 first, then ipv4

          4f   : ipv4 first, then ipv6

  -d, --dns-server <DNS_SERVER>
          Dns server to use for looking up.

          Value can be an ip address or 'google', 'cloudflare' or 'quad9'

  -t
          Print table headers

  -j <J>
          Number of parallel requests

  -h, --help
          Print help information (use `-h` for a summary)

  -V, --version
          Print version information
```