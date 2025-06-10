import ipaddress
import socket
import tldextract

def extract_domains(url):
    """
    Extracts the domain and subdomain from a given URL.

    Args:
        url (str): The input URL.

    Returns:
        tuple: A tuple (domain, subdomain).
            - domain: The main domain with TLD (e.g., "example.com").
            - subdomain: Full subdomain including nested levels (e.g., "sub.example.com").
                        If the URL starts with 'www', it is removed.
    """

    extracted = tldextract.extract(url)
    if not extracted.suffix or not extracted.domain:
        return None, None

    domain = f"{extracted.domain}.{extracted.suffix}"
    subdomain = extracted.subdomain or None
    return domain, subdomain

def resolve_dns(domain):
    """
    Resolves the DNS for a given domain and returns a list of public IP addresses.

    Args:
        domain (str): The domain to resolve.

    Returns:
        list or None: A list of public (global) IP addresses, or None if resolution fails
                      or the input is invalid.
    """
    if domain is None:
        return None
    try:
        ips = socket.gethostbyname_ex(domain)[-1] # Get all resolved IPs
        public_ips = [ip for ip in ips if ipaddress.ip_address(ip).is_global]
        return public_ips
    except socket.error:
        return None
