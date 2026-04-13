import re
import math
from collections import Counter
import difflib

def calc_entropy(s):
    if not s:
        return 0
    p, lns = Counter(s), float(len(s))
    return -sum(count/lns * math.log2(count/lns) for count in p.values())

top_brands = ['paypal', 'google', 'amazon', 'microsoft', 'apple', 'facebook', 'netflix']

def get_impersonation_score(domain, brands):
    """
    Returns a similarity score only for near-matches, not exact matches.
    Exact matches (real brands) return 0 — they're not impersonators.
    """
    # Use the registrable part only (strip TLD) to compare against brand names
    parts = domain.split('.')
    base = parts[-2] if len(parts) >= 2 else domain  # e.g. "paypal" from "paypal.com"

    scores = []
    for brand in brands:
        ratio = difflib.SequenceMatcher(None, base, brand).ratio()
        # Exact match = legitimate brand domain, not impersonation
        if base == brand:
            scores.append(0.0)
        else:
            scores.append(ratio)
    return max(scores)

def extract_features(url):
    url = str(url).lower().strip()
    url_clean = re.sub(r'https?://', '', url)
    domain = url_clean.split('/')[0]

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

        # Brand names removed — they're captured by brand_similarity/brand_impersonation
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

        # Leet-speak / typosquatting patterns
        'brand_impersonation': 1 if re.search(
                                   r'(paypa1|g00gle|amaz0n|micros0ft|app1e|faceb00k|netfl1x)',
                                   url_clean) else 0,

        'long_domain':         1 if len(domain) > 30 else 0,
        'many_subdomains':     max(len(domain.split('.')) - 2, 0),
        'path_length':         len(url_clean.split('/', 1)[1]) if '/' in url_clean else 0,
        'char_entropy':        calc_entropy(url_clean),

        # Fixed: real brand domains now score 0, near-matches score high
        'brand_similarity':    get_impersonation_score(domain, top_brands),
    }
