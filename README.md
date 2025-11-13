# 🕷️ CacheShadow

**Advanced Web Cache Poisoning Scanner**  
*"Exposing the shadows in your cache"*

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

## 📋 Overview

CacheShadow is a comprehensive security tool designed to detect cache poisoning vulnerabilities in web applications. It tests for multiple attack vectors including unkeyed headers, query parameter pollution, path normalization issues, and more.

## ✨ Features

- ✅ **27+ Unkeyed Header Tests** - X-Forwarded-Host, X-Original-URL, Host, etc.
- ✅ **Query Parameter Injection** - Tests 15+ common parameters
- ✅ **Path Normalization** - 14+ path variation tests
- ✅ **HTTP Method Override** - Tests method override headers
- ✅ **Fat GET Requests** - GET with body content testing
- ✅ **Header Normalization** - Case and format variation tests
- ✅ **Response Splitting** - CRLF injection detection
- ✅ **Vary Header Bypass** - Cache key enforcement testing
- ✅ **Cache Deception** - Static extension tricks
- ✅ **Multi-threaded Scanning** - Fast path enumeration
- ✅ **Confidence Scoring** - High/Medium/Low ratings
- ✅ **Proxy Support** - Works with Burp Suite/ZAP
- ✅ **JSON Export** - Detailed reporting

## 🚀 Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Setup
```bash
# Clone the repository
git clone https://github.com/1amrahul/CacheShadow.git
cd CacheShadow

# Install dependencies
pip install -r requirements.txt

# Make executable (Linux/Mac)
chmod +x cache_poison_scanner.py

# Or use the installer
chmod +x install.sh
./install.sh
```

## 📖 Usage

### Basic Scan
```bash
python3 cache_poison_scanner.py -u https://example.com
```

### Verbose Mode with Export
```bash
python3 cache_poison_scanner.py -u https://example.com -v -o results.json
```

### Multi-path Crawl Scan
```bash
python3 cache_poison_scanner.py -u https://example.com --crawl --threads 5
```

### Through Proxy (Burp Suite)
```bash
python3 cache_poison_scanner.py -u https://example.com --proxy http://127.0.0.1:8080 --no-ssl-verify
```

### Inspect Cache Configuration Only
```bash
python3 cache_poison_scanner.py -u https://example.com --inspect-only
```

### Custom Timing
```bash
python3 cache_poison_scanner.py -u https://example.com --delay 2 --timeout 15
```

## 🎯 Command Line Options
```
Required:
  -u, --url URL              Target URL to scan

Optional:
  -v, --verbose              Enable verbose output
  -o, --output FILE          Save results to JSON file
  --timeout SECONDS          Request timeout (default: 10)
  --delay SECONDS            Delay between requests (default: 1.0)
  --proxy URL                HTTP proxy (e.g., http://127.0.0.1:8080)
  --threads NUM              Thread count for scanning (default: 2)
  --crawl                    Crawl and test common paths
  --inspect-only             Only inspect caching configuration
  --no-ssl-verify            Disable SSL verification
  -h, --help                 Show help message
```

## 🔬 Test Categories

### 1. Unkeyed Headers
Tests headers that may not be included in the cache key:
- Host, X-Forwarded-Host, X-Original-Host
- X-Forwarded-Proto, X-Forwarded-Scheme
- X-Real-IP, CF-Connecting-IP, True-Client-IP
- Referer, Origin, User-Agent
- And 15+ more headers

### 2. Query Parameter Injection
Tests common query parameters:
- utm_source, utm_medium, utm_campaign
- fbclid, gclid, ref, source
- callback, redirect, return, next

### 3. Path Variations
Tests path normalization:
- `/%2e/`, `//`, `/./`, `/%2e%2e/`
- `/;/`, `/..;/`, `/%00/`, `/%0a/`

### 4. Advanced Techniques
- HTTP Method Override (X-HTTP-Method-Override)
- Fat GET Requests (GET with body)
- Header Normalization (case, underscores)
- Response Splitting (CRLF injection)
- Vary Header Bypass
- Cache Deception Attacks

## 📊 Output Example
```
[*] Testing Unkeyed Headers for Cache Poisoning
[!] Reflection found with X-Forwarded-Host, but not cached (yet).
[!!!] CACHE POISONING CONFIRMED!
      Header: X-Original-URL → Payload: evil.example.com/POISON-abc123def4
      Poisoned URL: https://target.com

SCAN COMPLETED
Found 3 potential vulnerabilities:
  - High Confidence: 2
  - Medium Confidence: 1
```

## 🛡️ Mitigation Recommendations

The tool provides automatic mitigation advice:

1. **Cache Key Configuration** - Include all user-controllable headers
2. **Vary Header** - Specify which headers affect caching
3. **Input Sanitization** - Validate and sanitize all headers
4. **Reflection Prevention** - Avoid reflecting untrusted input
5. **Normalization** - Implement proper cache key normalization
6. **Private Content** - Use `Cache-Control: private` for user data

## ⚠️ Legal Disclaimer

**WARNING:** This tool is designed for authorized security testing only.

- ✅ Use only on systems you own or have explicit written permission to test
- ✅ Obtain proper authorization before scanning
- ✅ Follow responsible disclosure practices
- ❌ Never use on production systems without approval
- ❌ Unauthorized testing may be illegal in your jurisdiction

The authors assume no liability for misuse or damage caused by this tool.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Inspired by research from PortSwigger, James Kettle, and the security community
- Built upon techniques documented in cache poisoning research papers
- Thanks to all contributors and testers

## 📧 Contact

- GitHub Issues: [Report bugs or request features](https://github.com/CacheShadow/cacheshadow/issues)

## 🔗 Resources

- [PortSwigger Cache Poisoning Research](https://portswigger.net/research/practical-web-cache-poisoning)
- [OWASP Cache Poisoning](https://owasp.org/www-community/attacks/Cache_Poisoning)
- [Web Cache Deception Attack](https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html)

---

**Made with ❤️ for security researchers**