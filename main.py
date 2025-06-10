import argparse
import json
from domain_analyzer import extract_domains, resolve_dns

def process_input(urls):
    """
    Processes a list of URLs to extract domains, subdomains, and optionally resolve public IPs.

    Args:
        urls (list): List of URL strings to analyze.

    Returns:
        list: A list of dictionaries with keys: domain, subdomain(s), and IP address(es).
    """
    aggregated = {}

    for url in urls:
        domain, subdomain = extract_domains(url)

        if domain is None:
            continue  # Skip invalid URLs or IP addresses

        ips = resolve_dns(domain) or []

        # Initialize data structure for this domain if not already present
        if domain not in aggregated:
            aggregated[domain] = {
                "subdomains": set(),
                "ip_addresses": set()
            }

        # Add subdomain (empty string if none)
        aggregated[domain]["subdomains"].add(subdomain or "")

        # Add resolved IPs
        for ip in ips:
            aggregated[domain]["ip_addresses"].add(ip)

    # Format the results for output
    results = []
    for domain, data in aggregated.items():
        results.append({
            "domain": domain,
            "subdomain": ", ".join(sorted(data["subdomains"])),
            "ip_addresses": sorted(data["ip_addresses"])
        })

    return results

def print_results(results):
    """
    Display the processed domain results in a formatted table.

    Args:
        results (list): List of dictionaries with keys 'domain', 'subdomain', and 'ip_addresses'.
    """
    header = "{:<25} | {:<30} | {:<40}".format("Domain", "Sub-domains", "IP Addresses")
    separator = "=" * len(header)

    print(header)
    print(separator)

    for entry in results:
        domain = entry.get("domain", "N/A")
        subdomains = entry.get("subdomain", "N/A")
        ip_addresses = entry.get("ip_addresses", [])

        if ip_addresses:
            ip_str = ", ".join(ip_addresses)
        else:
            ip_str = "N/A"

        print("{:<25} | {:<30} | {:<40}".format(domain, subdomains, ip_str))



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract domain info from URLs")
    parser.add_argument("-u", "--url", nargs="+", help="One or more URLs to process")
    parser.add_argument("-f", "--file", type=str, help="Path to file containing URLs (one per line)")
    parser.add_argument("-o", "--output", type=str, help="Output results to JSON file")
    
    args = parser.parse_args()

    urls = []

    # Populate URL list from CLI or file
    if args.url:
        urls.extend(args.url)
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                urls.extend(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            print(f"[!] File not found : {args.file}")
            exit(1)
    else:
        print("[!] Please provide -u/--url or -f/--file.")
        parser.print_help()
        exit(1)

    # Process the URLs
    results = process_input(urls)

    if not results:
        print("[!] No valid domain found.")
        exit(0)

    # Output results to JSON file or terminal
    if args.output:
        with open(args.output, 'w') as out_file:
            json.dump(results, out_file, indent=4)
        print(f"[+] Results saved to : {args.output}")
    else:
        print_results(results)
