import re
import math
from collections import Counter
import difflib

def calc_entropy(s):
    if not s:
        return 0
    p, lns = Counter(s), float(len(s))
    return -sum(count/lns * math.log2(count/lns) for count in p.values())

top_brands = ['paypal', 'google', 'amazon', 'microsoft', 'apple', 'facebook', 'netflix', 'youtube']

# Known legitimate domains that should never be flagged
KNOWN_SAFE_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
    'microsoft.com', 'apple.com', 'netflix.com', 'paypal.com',
    'twitter.com', 'instagram.com', 'linkedin.com', 'github.com',
    'wikipedia.org', 'reddit.com', 'yahoo.com', 'bing.com',
    'live.com', 'outlook.com', 'office.com', 'windows.com',
    'docs.google.com', 'drive.google.com', 'mail.google.com',
    'maps.google.com', 'play.google.com', 'accounts.google.com',
}

def get_root_domain(domain):
    """Extract root domain e.g. docs.google.com -> google.com"""
    parts = domain.split('.')
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}"
    return domain

def get_impersonation_score(domain, brands):
    parts = domain.split('.')
    base = parts[-2] if len(parts) >= 2 else domain

    scores = []
    for brand in brands:
        ratio = difflib.SequenceMatcher(None, base, brand).ratio()
        if base == brand:
            scores.append(0.0)
        else:
            scores.append(ratio)
    return max(scores)

def is_known_safe(domain):
    """Returns 1 if domain is a known legitimate domain"""
    domain = domain.lower().replace('www.', '')
    root = get_root_domain(domain)
    if domain in KNOWN_SAFE_DOMAINS:
        return 1
    if root in KNOWN_SAFE_DOMAINS:
        return 1
    # Check if root domain matches a brand exactly
    parts = domain.split('.')
    if len(parts) >= 2:
        base = parts[-2]
        if base in [b for b in top_brands]:
            tld = parts[-1]
            if tld in ['com', 'org', 'net', 'edu', 'gov', 'io', 'co']:
                return 1
    return 0

def extract_features(url):
    url = str(url).lower().strip()
    url_clean = re.sub(r'https?://', '', url)
    domain = url_clean.split('/')[0]
    domain_no_www = domain.replace('www.', '')

    # Check if this is a known safe domain
    known_safe = is_known_safe(domain_no_www)

    return {
        'url_length':          len(url_clean),
        'domain_length':       len(domain),
        'num_dots':            url_clean.count('.'),
        'has_ip':              1 if re.search(r'\d+\.\d+\.\d+\.\d+', url_clean) else 0,
        'num_subdirs':         url_clean.count('/'),
        'num_params':          url_clean.count('?') + url_clean.count('&'),
        'num_hyphens':         url_clean.count('-'),
        'num_at':              url_clean.count('@'),
        'num_subdomains':      max(len(domain.split('.')) - 2, 0),

        'suspicious_words':    sum(1 for w in [
                                   'login', 'verify', 'secure', 'account', 'update',
                                   'banking', 'confirm', 'password', 'signin',
                                   'webscr', 'free', 'lucky', 'service', 'access'
                               ] if w in url_clean),

        'digits_count':        sum(c.isdigit() for c in url_clean),
        'special_chars':       sum(1 for c in url_clean if c in '-_%@=~+'),

        'has_suspicious_tld':  1 if any(domain.endswith(t) for t in [
                                   '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq',
                                   '.top', '.click', '.link', '.online', '.site',
                                   '.icu', '.pw', '.cc', '.ru', '.cn'
                               ]) else 0,

        'domain_has_numbers':  1 if re.search(r'\d', domain) else 0,
        'has_multiple_subdomains': 1 if len(domain.split('.')) > 3 else 0,
        'url_has_at_sign':     1 if '@' in url_clean else 0,
        'double_slash':        1 if '//' in url_clean else 0,
        'num_digits_domain':   sum(c.isdigit() for c in domain),

        'brand_impersonation': 1 if re.search(
                                   r'(paypa1|g00gle|amaz0n|micros0ft|app1e|faceb00k|netfl1x)',
                                   url_clean) else 0,

        'long_domain':         1 if len(domain) > 30 else 0,
        'many_subdomains':     max(len(domain.split('.')) - 2, 0),
        'path_length':         len(url_clean.split('/', 1)[1]) if '/' in url_clean else 0,
        'char_entropy':        calc_entropy(url_clean),
        'brand_similarity':    get_impersonation_score(domain, top_brands),

        # NEW: directly flags known legitimate domains
        # This prevents the model from flagging google.com, youtube.com etc.
        'is_known_safe_domain': known_safe,

        # NEW: ratio of digits to total URL length (phishing URLs tend to have more digits)
        'digit_ratio':         sum(c.isdigit() for c in url_clean) / max(len(url_clean), 1),

        # NEW: number of suspicious TLD-like patterns in the path
        'has_brand_in_subdomain': 1 if any(
            brand in domain.split('.')[0]
            for brand in top_brands
            if domain.split('.')[0] != brand
        ) else 0,
    }