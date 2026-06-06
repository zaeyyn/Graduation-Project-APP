from utils import extract_features

urls = [
    'https://www.google.com',
    'http://paypa1-verify.net/secure/login',
    'https://www.youtube.com',
]

for url in urls:
    f = extract_features(url)
    print(f'URL: {url}')
    print(f'  is_known_safe_domain: {f["is_known_safe_domain"]}')
    print(f'  brand_impersonation: {f["brand_impersonation"]}')
    print(f'  suspicious_words: {f["suspicious_words"]}')
    print()