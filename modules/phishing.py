from urllib.parse import urlparse
import ipaddress

SUSPICIOUS_WORDS = ["login", "verify", "secure", "account", "update",
                    "bank", "signin", "confirm", "password", "wallet"]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"]
RISKY_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click"]


def check_url(url):
    url = url.strip()
    has_scheme = url.lower().startswith(("http://", "https://"))
    if not has_scheme:
        url = "http://" + url

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    reasons = []
    score = 0

    if len(url) > 75:
        score += 1
        reasons.append("The URL is very long")

    try:
        ipaddress.ip_address(host)
        score += 2
        reasons.append("It uses an IP address instead of a domain name")
    except ValueError:
        pass

    if "@" in url:
        score += 2
        reasons.append("It contains an @ symbol, which can hide the real destination")

    if has_scheme and parsed.scheme == "http":
        score += 1
        reasons.append("It does not use HTTPS")

    if host.count(".") > 3:
        score += 1
        reasons.append("It has too many subdomains")

    if "-" in host:
        score += 1
        reasons.append("The domain contains hyphens")

    if "xn--" in host:
        score += 2
        reasons.append("The domain uses punycode, which can imitate real brands")

    if host in SHORTENERS:
        score += 1
        reasons.append("It uses a link shortener that hides the real destination")

    if any(host.endswith(tld) for tld in RISKY_TLDS):
        score += 2
        reasons.append("It ends with a domain type often used in scams")

    found = [word for word in SUSPICIOUS_WORDS if word in url.lower()]
    if found:
        score += 2
        reasons.append("It contains suspicious words: " + ", ".join(found))

    percent = min(100, score * 10)

    if percent >= 40:
        verdict = "Likely phishing"
    elif percent >= 20:
        verdict = "Suspicious"
    else:
        verdict = "Looks safe"

    return {"verdict": verdict, "score": score, "percent": percent, "reasons": reasons}


if __name__ == "__main__":
    print(check_url("https://www.google.com"))
    print(check_url("http://192.168.1.5/login@bank"))