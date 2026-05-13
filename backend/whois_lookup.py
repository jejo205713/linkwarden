import whois
import dns.resolver
from urllib.parse import urlparse
import datetime

def get_domain_info(url):
    """
    Extracts WHOIS domain age, registrar, and DNS records.
    Handles errors and complex WHOIS response types.
    """
    domain = urlparse(url).netloc
    if not domain:
        domain = url
        
    info = {
        "age_days": None, 
        "dns_records": 0, 
        "registrar": "Unknown"
    }
    
    # 1. WHOIS Lookup
    try:
        w = whois.whois(domain)
        
        # Safely extract Creation Date (Some domains return lists, some strings)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if isinstance(creation_date, datetime.datetime):
            age = (datetime.datetime.now() - creation_date).days
            info["age_days"] = age
            
        # Safely extract Registrar
        registrar = w.registrar
        if isinstance(registrar, list):
            info["registrar"] = str(registrar[0])
        elif isinstance(registrar, str):
            info["registrar"] = registrar
            
    except Exception:
        pass # If WHOIS fails, leave as default/None
        
    # 2. DNS Lookup
    try:
        answers = dns.resolver.resolve(domain, 'A')
        info["dns_records"] = len(answers)
    except Exception:
        pass # If DNS fails, leave as 0
        
    return info

# ALIAS for internal compatibility
get_whois_info = get_domain_info