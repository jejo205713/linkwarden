import requests

def expand_url(url):
    """Safely resolves shortened URLs."""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        response = requests.head(url, allow_redirects=True, timeout=5, headers=headers)
        return str(response.url), int(len(response.history))
    except Exception:
        return str(url), 0