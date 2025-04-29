import requests

# List of important security headers to check
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Expect-CT",
    "Feature-Policy",  # Deprecated but some sites still use it
]

def check_security_headers(url):
    try:
        # Send a HEAD request (faster, but fallback to GET if not allowed)
        try:
            response = requests.head(url, allow_redirects=True, timeout=10)
        except requests.exceptions.RequestException:
            response = requests.get(url, allow_redirects=True, timeout=10)
        
        headers = response.headers
        print(f"\n[+] Checking security headers for {url}\n")

        results = {}
        for header in SECURITY_HEADERS:
            if header in headers:
                results[header] = f"✅ Present ({headers[header]})"
            else:
                results[header] = "❌ Missing"

        for header, status in results.items():
            print(f"{header}: {status}")

        return results

    except requests.exceptions.RequestException as e:
        print(f"[-] Error accessing {url}: {e}")
        return None

if __name__ == "__main__":
    target_url = input("Enter the URL (with http/https): ").strip()
    if not target_url.startswith(("http://", "https://")):
        print("[-] Please include http:// or https:// in the URL.")
    else:
        check_security_headers(target_url)
