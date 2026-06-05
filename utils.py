import re
import math
from collections import Counter
import difflib

def calc_entropy(s):
    if not s:
        return 0
    p, lns = Counter(s), float(len(s))
    return -sum(count/lns * math.log2(count/lns) for count in p.values())

# Known legitimate TLDs used by real companies
TRUSTED_TLDS = {'.com', '.org', '.net', '.edu', '.gov', '.io', '.co.uk', '.ac.uk'}

# Known phishing/suspicious TLDs
SUSPICIOUS_TLDS = {
    '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click',
    '.link', '.online', '.site', '.icu', '.pw', '.cc', '.ru', '.cn',
    '.buzz', '.fun', '.live', '.stream', '.gdn', '.racing', '.win',
    '.download', '.loan', '.date', '.faith', '.trade', '.accountant'
}

# Well-known legitimate second-level domains
KNOWN_LEGITIMATE_DOMAINS = {
    'google', 'youtube', 'facebook', 'amazon', 'microsoft', 'apple',
    'netflix', 'paypal', 'twitter', 'instagram', 'linkedin', 'github',
    'wikipedia', 'reddit', 'yahoo', 'bing', 'live', 'outlook', 'office',
    'windows', 'whatsapp', 'tiktok', 'snapchat', 'pinterest', 'twitch',
    'spotify', 'adobe', 'dropbox', 'icloud', 'cloudflare', 'stackoverflow',
    'bbc', 'cnn', 'nytimes', 'theguardian', 'reuters', 'bloomberg',
    'techcrunch', 'theverge', 'wired', 'forbes', 'shopify', 'ebay',
    'etsy', 'walmart', 'coursera', 'udemy', 'duolingo', 'medium',
    'wordpress', 'godaddy', 'namecheap', 'hostinger', 'digitalocean',
    'stripe', 'wise', 'revolut', 'notion', 'slack', 'zoom', 'canva',
    'figma', 'atlassian', 'trello', 'discord', 'telegram', 'signal',
    'heroku', 'vercel', 'netlify', 'docker', 'npmjs', 'pypi',
}

# Brand names for impersonation detection
TOP_BRANDS = [
    'paypal', 'google', 'amazon', 'microsoft', 'apple', 'facebook',
    'netflix', 'youtube', 'instagram', 'twitter', 'linkedin', 'dropbox',
    'whatsapp', 'spotify', 'adobe', 'ebay', 'walmart', 'chase', 'wellsfargo'
]

def get_impersonation_score(base, brands):
    """Returns similarity score — 0 for exact match (real brand), high for near-match"""
    scores = []
    for brand in brands:
        ratio = difflib.SequenceMatcher(None, base, brand).ratio()
        scores.append(0.0 if base == brand else ratio)
    return max(scores) if scores else 0.0

def extract_features(url):
    url = str(url).lower().strip()
    url_clean = re.sub(r'https?://', '', url)
    domain_with_www = url_clean.split('/')[0]
    domain = domain_with_www.replace('www.', '')
    parts = domain.split('.')

    # Extract components
    path = url_clean.split('/', 1)[1] if '/' in url_clean else ''
    sld = parts[-2] if len(parts) >= 2 else ''
    subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''

    # Is this a known legitimate domain?
    is_legitimate = 1 if sld in KNOWN_LEGITIMATE_DOMAINS else 0

    # Has suspicious TLD?
    has_suspicious_tld = 1 if any(domain.endswith(t) for t in SUSPICIOUS_TLDS) else 0

    # Has trusted TLD?
    has_trusted_tld = 1 if any(domain.endswith(t) for t in TRUSTED_TLDS) else 0

    # Leet-speak brand impersonation
    has_leet_brand = 1 if re.search(
        r'(paypa1|g00gle|amaz0n|micros0ft|app1e|faceb00k|netfl1x|y0utube|tw1tter)',
        url_clean
    ) else 0

    # Brand in subdomain
    brand_in_subdomain = 0
    if subdomain:
        for brand in TOP_BRANDS:
            if brand in subdomain and sld != brand:
                brand_in_subdomain = 1
                break

    # Suspicious keywords
    suspicious_count = sum(1 for w in [
        'login', 'verify', 'secure', 'account', 'update', 'banking',
        'confirm', 'password', 'signin', 'webscr', 'free', 'lucky',
        'service', 'access', 'alert', 'suspend', 'locked', 'unusual',
        'validate', 'authenticate', 'restore', 'recover', 'urgent',
        'limited', 'expire', 'click', 'win', 'prize', 'offer'
    ] if w in url_clean)

    # Brand similarity
    brand_similarity = get_impersonation_score(sld, TOP_BRANDS)

    # Number of subdomains
    num_subdomains = max(len(parts) - 2, 0)

    # Digit ratio in domain
    domain_digits = sum(c.isdigit() for c in domain)
    digit_ratio = domain_digits / max(len(domain), 1)

    return {
        'url_length':               len(url_clean),
        'domain_length':            len(domain),
        'path_length':              len(path),
        'num_dots':                 url_clean.count('.'),
        'num_hyphens':              url_clean.count('-'),
        'num_at':                   url_clean.count('@'),
        'num_subdirs':              url_clean.count('/'),
        'num_params':               url_clean.count('?') + url_clean.count('&'),
        'num_subdomains':           num_subdomains,
        'domain_has_numbers':       1 if re.search(r'\d', domain) else 0,
        'num_digits_domain':        domain_digits,
        'digit_ratio':              digit_ratio,
        'domain_length_gt_30':      1 if len(domain) > 30 else 0,
        'has_ip_address':           1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0,
        'has_multiple_subdomains':  1 if num_subdomains > 1 else 0,
        'has_suspicious_tld':       has_suspicious_tld,
        'has_trusted_tld':          has_trusted_tld,
        'is_legitimate_domain':     is_legitimate,
        'url_has_at_sign':          1 if '@' in url_clean else 0,
        'double_slash_redirect':    1 if url_clean.count('//') > 1 else 0,
        'suspicious_words':         suspicious_count,
        'brand_impersonation':      has_leet_brand,
        'brand_in_subdomain':       brand_in_subdomain,
        'brand_similarity':         brand_similarity,
        'char_entropy':             calc_entropy(url_clean),
        'domain_entropy':           calc_entropy(domain),
        'special_chars':            sum(1 for c in url_clean if c in '-_%@=~+#$'),
        'digits_count':             sum(c.isdigit() for c in url_clean),
    }