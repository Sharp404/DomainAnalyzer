# Domain Analyzer

A simple CLI tool to extract and aggregate domains, subdomains, and public IP addresses from URLs.

## Features

- Extracts domain and subdomain from a list of URLs
- Resolves public IP addresses associated with the domains
- Supports input via command line or from a file
- Aggregates results by domain with all associated subdomains and IPs
- Outputs results in a formatted terminal table or JSON file

## Usage

Run the CLI tool with URLs or a file of URLs :

```bash
# Process single or multiple URLs
python3 main.py -u https://example.com/path https://sub.example.com

# Process URLs from a file (one URL per line)
python3 main.py -f urls.txt

# Save output to JSON file
python3 main.py -u https://example.com -o results.json
```

### Exemple Output

```bash
python3 main.py -u https://www.google.com/search? https://www.microsoft.com https://en.wikipedia.org/wiki/Main_Page http://placeh
older.com http://ftp.example.com sub.example.com https://dummy-website.com
```

![cli_output](https://github.com/Sharp404/DomainAnalyzer/blob/main/assets/cli_output.png)

