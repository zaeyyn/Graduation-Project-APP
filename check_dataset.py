import pandas as pd

df = pd.read_csv('malicious_phish.csv')
df['url_length'] = df['url'].str.len()

print("Average URL length:")
print(f"  Legitimate (status=1): {df[df['status']==1]['url_length'].mean():.1f} chars")
print(f"  Phishing   (status=0): {df[df['status']==0]['url_length'].mean():.1f} chars")

print("\nSample legitimate URLs:")
print(df[df['status']==1]['url'].head(10).tolist())

print("\nSample phishing URLs:")
print(df[df['status']==0]['url'].head(10).tolist())