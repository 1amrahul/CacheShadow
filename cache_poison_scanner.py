import sys
import time
import hashlib
import random
import string
import argparse
import json
import requests
import warnings
import re
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode, urljoin
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

warnings.filterwarnings("ignore") 

class CachePoisoningScanner:
    def __init__(self, target_url: str, verbose: bool = False, timeout: int = 10, 
                 retry_interval: float = 1.0, proxy: Optional[str] = None, 
                 threads: int = 2, verify_ssl: bool = False):
        self.target_url = target_url.rstrip('/')
        self.verbose = verbose
        self.timeout = timeout
        self.retry_interval = retry_interval
        self.threads = threads
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.verify_ssl = verify_ssl
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Connection': 'close'
        })
        
        self.results = []
        self.baseline_response = None
        
        self.cache_headers = [
            'age', 'x-cache', 'x-cache-status', 'x-cache-hits', 
            'cf-cache-status', 'x-served-by', 'x-proxy-cache',
            'x-drupal-cache', 'x-nginx-cache', 'x-varnish-cache',
            'x-fastly-cache-status'
        ]
        
    def log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "INFO": "[*]",
            "SUCCESS": "[+]",
            "WARNING": "[!]",
            "ERROR": "[-]",
            "CRITICAL": "[!!!]",
            "CHECK": "[?]"
        }.get(level, "[*]")
        print(f"{timestamp} {prefix} {message}")
    
    def generate_unique_marker(self) -> str:
        t = str(time.time()).encode()
        return "POISON-" + hashlib.sha1(t).hexdigest()[:10]
    
    def generate_cache_buster(self) -> str:
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    
    def compute_body_hash(self, text: str) -> str:
        return hashlib.sha1((text or "").encode()).hexdigest()[:10]
    
    def is_cached(self, response: requests.Response) -> Tuple[bool, str]:
        for header in self.cache_headers:
            if header in response.headers:
                value = response.headers[header].lower()
                if 'hit' in value or 'cached' in value:
                    return True, f"{header}: {response.headers[header]}"
                if header == 'age':
                    try:
                        age_val = int(response.headers[header])
                        if age_val > 0:
                            return True, f"Age: {age_val}"
                    except ValueError:
                        pass
        
        return False, "No cache indicators found"
    
    def responses_match(self, resp1: requests.Response, resp2: requests.Response, 
                       strict: bool = False) -> bool:
        if resp1.status_code != resp2.status_code:
            return False
        
        if resp1.text == resp2.text:
            # Check for cache headers
            if any(h in resp2.headers for h in self.cache_headers):
                return True
            if strict:
                return False
            # If identical on quick 2nd request, likely cached
            return True
        
        return False
    
    def send_request(self, url: str, method: str = "GET", headers: Optional[Dict] = None, 
                    params: Optional[Dict] = None, data: Optional[str] = None,
                    allow_redirects: bool = True) -> Optional[requests.Response]:
        try:
            merged_headers = dict(self.session.headers)
            if headers:
                merged_headers.update(headers)
            
            r = self.session.request(
                method, url, 
                headers=merged_headers, 
                params=params, 
                data=data,
                timeout=self.timeout, 
                allow_redirects=allow_redirects,
                proxies=self.proxies,
                verify=self.verify_ssl
            )
            return r
        except requests.RequestException as e:
            if self.verbose:
                self.log(f"Request error: {e}", "ERROR")
            return None
    
    def inspect_caching_configuration(self, url: str):
        self.log(f"\nInspecting caching configuration for: {url}", "INFO")
        self.log("="*60, "INFO")
        
        try:
            response = self.send_request(url)
            if not response:
                return
            
            self.log(f"Status Code: {response.status_code}", "INFO")
            
            vary_header = response.headers.get('Vary', 'None')
            self.log(f"Vary Header: {vary_header}", "INFO")
            if vary_header != 'None':
                self.log("  → These request headers are included in cache key", "INFO")
            
            cache_control = response.headers.get('Cache-Control', 'None')
            self.log(f"Cache-Control: {cache_control}", "INFO")
            
            age_header = response.headers.get('Age', 'N/A')
            self.log(f"Age: {age_header} seconds", "INFO")
            
            etag = response.headers.get('ETag', 'None')
            self.log(f"ETag: {etag}", "INFO")

            cdn_headers = {
                'Server': response.headers.get('Server', 'Unknown'),
                'X-Cache': response.headers.get('X-Cache', 'N/A'),
                'CF-Cache-Status': response.headers.get('CF-Cache-Status', 'N/A'),
                'X-Served-By': response.headers.get('X-Served-By', 'N/A'),
            }
            
            self.log("\nCDN/Cache Detection:", "INFO")
            for header, value in cdn_headers.items():
                if value != 'N/A' and value != 'Unknown':
                    self.log(f"  {header}: {value}", "INFO")
            
            if self.verbose:
                self.log("\nFull Response Headers:", "INFO")
                for header, value in response.headers.items():
                    print(f"  {header}: {value}")
            
        except Exception as e:
            self.log(f"Error inspecting caching config: {str(e)}", "ERROR")
    
    def get_baseline(self):
        """Get baseline response for comparison"""
        self.log("\nEstablishing baseline...", "INFO")
        self.log("="*60, "INFO")
        
        self.baseline_response = self.send_request(self.target_url)
        if not self.baseline_response:
            self.log("Could not fetch baseline response", "ERROR")
            return None
        
        self.log(f"Baseline Status: {self.baseline_response.status_code}", "INFO")
        self.log(f"Body Length: {len(self.baseline_response.text or '')}", "INFO")
        self.log(f"Body Hash: {self.compute_body_hash(self.baseline_response.text)}", "INFO")

        time.sleep(self.retry_interval)
        baseline2 = self.send_request(self.target_url)
        
        if baseline2 and self.responses_match(self.baseline_response, baseline2):
            is_cached, status = self.is_cached(baseline2)
            if is_cached:
                self.log("✓ Response appears cacheable", "SUCCESS")
                self.log(f"  Cache Status: {status}", "INFO")
            else:
                self.log("Response identical but no cache headers detected", "WARNING")
        else:
            self.log("URL may not be cached — results may be less reliable", "WARNING")
        
        return self.baseline_response
    
    def test_header_reflection_advanced(self, header_name: str, payload: str, 
                                       url: Optional[str] = None) -> Dict:
        """Advanced header reflection test with cache confirmation"""
        test_url = url or self.target_url
        
        if self.verbose:
            self.log(f"Testing header: {header_name} → payload: {payload}", "INFO")

        resp1 = self.send_request(test_url, headers={header_name: payload})
        if not resp1:
            return {'error': 'Request failed', 'header': header_name}
        
        reflected_in_origin = payload in (resp1.text or "")
        origin_hash = self.compute_body_hash(resp1.text)
        is_cached1, cache_status1 = self.is_cached(resp1)

        time.sleep(self.retry_interval)

        resp2 = self.send_request(test_url)
        if not resp2:
            return {'error': 'Probe request failed', 'header': header_name}
        
        payload_in_followup = payload in (resp2.text or "")
        followup_hash = self.compute_body_hash(resp2.text)
        is_cached2, cache_status2 = self.is_cached(resp2)
        responses_identical = self.responses_match(resp1, resp2)

        vulnerable = False
        confidence = "low"
        
        if reflected_in_origin and payload_in_followup:
            if is_cached2 or responses_identical:
                vulnerable = True
                confidence = "high"
                self.log(f"  [!!!] CACHE POISONING CONFIRMED!", "CRITICAL")
                self.log(f"       Header: {header_name} → Payload: {payload}", "CRITICAL")
            else:
                vulnerable = True
                confidence = "medium"
                self.log(f"  [!] Possible cache poisoning (low confidence)", "WARNING")
        elif reflected_in_origin:
            self.log(f"  [?] Reflection found but not cached (yet)", "CHECK")
            confidence = "reflection_only"
        
        if self.verbose:
            self.log(f"  reflected_in_origin: {reflected_in_origin}", "INFO")
            self.log(f"  payload_in_followup: {payload_in_followup}", "INFO")
            self.log(f"  origin_hash: {origin_hash}, followup_hash: {followup_hash}", "INFO")
            self.log(f"  cached_origin: {is_cached1}, cached_followup: {is_cached2}", "INFO")
        
        return {
            'vulnerable': vulnerable,
            'confidence': confidence,
            'header': header_name,
            'payload': payload,
            'reflected_in_origin': reflected_in_origin,
            'payload_in_followup': payload_in_followup,
            'cached_origin': is_cached1,
            'cached_followup': is_cached2,
            'cache_status': cache_status2,
            'origin_hash': origin_hash,
            'followup_hash': followup_hash,
            'responses_identical': responses_identical,
            'url': test_url
        }
    
    def test_unkeyed_headers(self):
        """Test common unkeyed headers for cache poisoning"""
        self.log("\n" + "="*60, "INFO")
        self.log("Testing Unkeyed Headers for Cache Poisoning", "INFO")
        self.log("="*60, "INFO")
        
        headers_to_test = [
            'Host',
            'X-Forwarded-Host',
            'X-Original-Host',
            'X-Host',
            'X-Forwarded-Proto',
            'X-Forwarded-Scheme',
            'X-Forwarded-For',
            'X-Real-IP',
            'X-Forwarded-Port',
            'X-Forwarded-Server',
            'Referer',
            'Origin',
            'User-Agent',
            'X-Original-URL',
            'X-Rewrite-URL',
            'X-Original-Method',
            'True-Client-IP',
            'X-Client-IP',
            'X-Custom-IP-Authorization',
            'CF-Connecting-IP',
            'X-Originating-IP',
            'X-Remote-IP',
            'X-Remote-Addr',
            'Forwarded',
            'X-WAP-Profile',
            'X-Arbitrary-Header',
            'X-Custom-Header'
        ]
        
        payloads = [
            'evil.example.com',
            'injected.example.com',
            'hacker.test',
            'attacker.com'
        ]
        
        for header in headers_to_test:
            for payload in payloads:
                marker = self.generate_unique_marker()
                combined_payload = f"{payload}/{marker}"
                
                result = self.test_header_reflection_advanced(header, combined_payload)
                
                if result.get('vulnerable') and result.get('confidence') in ['high', 'medium']:
                    self.results.append(result)
                    if result.get('confidence') == 'high':
                        break  
    
    def test_query_parameter_injection(self):
        """Test query parameter pollution for cache poisoning"""
        self.log("\n" + "="*60, "INFO")
        self.log("Testing Query Parameter Injection", "INFO")
        self.log("="*60, "INFO")
        
        query_param_candidates = [
            'v', 'ver', 'version', 'id', 'cache',
            'utm_source', 'utm_medium', 'utm_campaign',
            'fbclid', 'gclid', 'ref', 'source', 'callback',
            'redirect', 'return', 'next', 'url', 'dest'
        ]
        
        parsed = urlparse(self.target_url)
        base_qs = parse_qs(parsed.query)
        
        for param in query_param_candidates:
            marker = self.generate_unique_marker()
            qs = dict(base_qs)
            qs[param] = marker
            new_query = urlencode(qs, doseq=True)
            new_parts = parsed._replace(query=new_query)
            test_url = urlunparse(new_parts)
            
            if self.verbose:
                self.log(f"Testing param: {param} => marker {marker}", "INFO")
            
            resp1 = self.send_request(test_url)
            if not resp1:
                continue
            
            reflected_in_origin = marker in (resp1.text or "")
            
            time.sleep(self.retry_interval)
            
            resp2 = self.send_request(self.target_url)
            if not resp2:
                continue
            
            marker_in_followup = marker in (resp2.text or "")
            is_cached, cache_status = self.is_cached(resp2)
            
            if self.verbose:
                self.log(f"  reflected: {reflected_in_origin}, in_followup: {marker_in_followup}", "INFO")
            
            if reflected_in_origin:
                self.log(f"  → Origin reflects query param: {param}", "WARNING")
                if marker_in_followup:
                    self.log(f"  [!!!] CACHE POISONING via query param!", "CRITICAL")
                    self.results.append({
                        'vulnerable': True,
                        'confidence': 'high',
                        'type': 'query_param_injection',
                        'parameter': param,
                        'marker': marker,
                        'reflected_in_origin': reflected_in_origin,
                        'marker_in_followup': marker_in_followup,
                        'cached': is_cached,
                        'test_url': test_url
                    })
    
    def test_path_variations(self):
        """Test path normalization and variations for cache poisoning"""
        self.log("\n" + "="*60, "INFO")
        self.log("Testing Path Normalization / Variations", "INFO")
        self.log("="*60, "INFO")
        
        path_variations = [
            "", "/", "//", "/.", "/./", "/%2e/", "/%2e%2e/",
            "/%2f/", "/;/", "/..;/", "/%00/", "/%0a/", "/%0d/",
            "/.%2e/", "/.../"
        ]
        
        parsed = urlparse(self.target_url)
        orig_path = parsed.path or "/"
        
        for var in path_variations:
            marker = self.generate_unique_marker()
            new_path = orig_path.rstrip("/") + f"/{marker}{var}"
            new_parts = parsed._replace(path=new_path)
            test_url = urlunparse(new_parts)
            
            if self.verbose:
                self.log(f"Testing path: {test_url}", "INFO")
            
            resp1 = self.send_request(test_url)
            if not resp1:
                continue
            
            reflected = marker in (resp1.text or "")
            
            time.sleep(self.retry_interval)
            
            resp2 = self.send_request(self.target_url)
            if not resp2:
                continue
            
            marker_in_followup = marker in (resp2.text or "")
            
            if reflected and marker_in_followup:
                self.log(f"  [!!!] CACHE POISONING via path variation: {var}", "CRITICAL")
                self.results.append({
                    'vulnerable': True,
                    'confidence': 'high',
                    'type': 'path_variation',
                    'variation': var,
                    'marker': marker,
                    'test_url': test_url
                })
    
    def test_host_header_poisoning(self):
        self.log("\n" + "="*60, "INFO")
        self.log("Testing Host Header Poisoning", "INFO")
        self.log("="*60, "INFO")
        
        payloads = ['evil.example.com', 'attacker.com', 'injected.test']
        
        for payload in payloads:
            marker = self.generate_unique_marker()
            evil_host = f"{marker}.{payload}"
            
            result = self.test_header_reflection_advanced('Host', evil_host)
            
            if result.get('vulnerable') and result.get('confidence') == 'high':
                self.log("CRITICAL: Host header poisoning detected!", "CRITICAL")
                self.results.append(result)
                break
    
    def test_http_method_override(self):
        self.log("\n" + "="*60, "INFO")
        self.log("Testing HTTP Method Override Headers", "INFO")
        self.log("="*60, "INFO")
        
        override_headers = [
            'X-HTTP-Method-Override',
            'X-HTTP-Method',
            'X-Method-Override',
            '_method',
            'X-HTTP-Method-Override-Request'
        ]
        
        methods = ['POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
        
        for header in override_headers:
            for method in methods:
                cache_buster = self.generate_cache_buster()
                url = f"{self.target_url}?cb={cache_buster}"
                
                if self.verbose:
                    self.log(f"Testing {header}: {method}", "INFO")
                
                try:
                    resp = self.send_request(url, headers={header: method})
                    if not resp:
                        continue
                    
                    is_cached, cache_status = self.is_cached(resp)
                    
                    if is_cached and resp.status_code not in [405, 501]:
                        self.log(f"Method override cached: {header}={method} (Status: {resp.status_code})", "WARNING")
                        self.results.append({
                            'type': 'method_override',
                            'header': header,
                            'method': method,
                            'status': resp.status_code,
                            'cached': is_cached
                        })
                        
                except Exception as e:
                    if self.verbose:
                        self.log(f"Error: {str(e)}", "ERROR")
    
    def test_fat_get_request(self):
        """Test fat GET request (GET with body)"""
        self.log("\n" + "="*60, "INFO")
        self.log("Testing Fat GET Request", "INFO")
        self.log("="*60, "INFO")
        
        marker = self.generate_unique_marker()
        cache_buster = self.generate_cache_buster()
        url = f"{self.target_url}?cb={cache_buster}"
        
        payload = f"test_param={marker}"
        
        try:
            resp1 = self.send_request(url, method='GET', data=payload)
            if not resp1:
                return
            
            is_cached1, _ = self.is_cached(resp1)
            reflected = marker in (resp1.text or "")
            
            if self.verbose:
                self.log(f"Fat GET reflected: {reflected}, cached: {is_cached1}", "INFO")
            
            time.sleep(self.retry_interval)
            
            resp2 = self.send_request(url)
            if not resp2:
                return
            
            is_cached2, _ = self.is_cached(resp2)
            marker_in_followup = marker in (resp2.text or "")
            
            if is_cached2 and marker_in_followup:
                self.log("[!!!] Fat GET request poisoned the cache!", "CRITICAL")
                self.results.append({
                    'vulnerable': True,
                    'confidence': 'high',
                    'type': 'fat_get',
                    'marker': marker
                })
            elif is_cached1:
                self.log("Fat GET request was cached (investigate further)", "WARNING")
                
        except Exception as e:
            if self.verbose:
                self.log(f"Error: {str(e)}", "ERROR")
    
    def test_header_normalization(self):
        self.log("\n" + "="*60, "INFO")
        self.log("Testing Header Normalization", "INFO")
        self.log("="*60, "INFO")
        
        base_headers = ['X-Forwarded-Host', 'X-Original-URL', 'X-Host']
        
        for base_header in base_headers:
            test_variations = [
                base_header.replace('-', '_'),
                base_header + ' ',
                ' ' + base_header,
                base_header.lower(),
                base_header.upper(),
            ]
            
            for variant in test_variations:
                marker = self.generate_unique_marker()
                result = self.test_header_reflection_advanced(variant, f"evil.com/{marker}")
                
                if result.get('vulnerable') and result.get('confidence') == 'high':
                    self.log(f"[!!!] Header normalization vuln: '{variant}'", "CRITICAL")
                    self.results.append(result)
    
    def test_response_splitting(self):
        """Test for HTTP response splitting"""
        self.log("\n" + "="*60, "INFO")
        self.log("Testing HTTP Response Splitting", "INFO")
        self.log("="*60, "INFO")
        
        crlf_payloads = [
            '%0d%0aX-Injected: true',
            '%0aX-Injected: true',
            '%0dX-Injected: true',
            '\r\nX-Injected: true',
            '\nX-Injected: true',
            '\rX-Injected: true',
            '%0d%0a%0d%0a<script>alert(1)</script>',
        ]
        
        test_headers = ['X-Forwarded-Host', 'X-Original-URL', 'Referer', 'User-Agent']
        
        for header in test_headers:
            for payload in crlf_payloads:
                marker = self.generate_unique_marker()
                combined = f"{marker}{payload}"
                cache_buster = self.generate_cache_buster()
                url = f"{self.target_url}?cb={cache_buster}"
                
                try:
                    resp = self.send_request(url, headers={header: combined})
                    if not resp:
                        continue
                    
                    if 'X-Injected' in resp.headers or 'x-injected' in resp.text.lower():
                        self.log(f"[!!!] RESPONSE SPLITTING: {header}", "CRITICAL")
                        self.results.append({
                            'vulnerable': True,
                            'confidence': 'high',
                            'type': 'response_splitting',
                            'header': header,
                            'payload': payload
                        })
                        
                except Exception as e:
                    if self.verbose:
                        self.log(f"Error: {str(e)}", "ERROR")
    
    def test_cache_deception(self):
        """Test for cache deception attacks"""
        self.log("\n" + "="*60, "INFO")
        self.log("Testing Cache Deception", "INFO")
        self.log("="*60, "INFO")
        
        deception_extensions = [
            '.css', '.js', '.jpg', '.png', '.gif', '.ico', 
            '.woff', '.woff2', '.ttf', '.svg', '.mp4', '.pdf'
        ]
        
        parsed = urlparse(self.target_url)
        base_path = parsed.path or "/"
        
        for ext in deception_extensions:
            new_path = base_path.rstrip("/") + f"/deception{ext}"
            new_parts = parsed._replace(path=new_path)
            test_url = urlunparse(new_parts)
            
            if self.verbose:
                self.log(f"Testing: {test_url}", "INFO")
            
            try:
                resp = self.send_request(test_url, allow_redirects=False)
                if not resp:
                    continue
                
                is_cached, cache_status = self.is_cached(resp)
                
                if is_cached and resp.status_code == 200:
                    dynamic_indicators = ['session', 'csrf', 'token', 'user', 'account', 'login']
                    has_dynamic = any(ind in resp.text.lower() for ind in dynamic_indicators)
                    
                    if has_dynamic:
                        self.log(f"[!] Cache deception potential: {ext}", "WARNING")
                        self.results.append({
                            'type': 'cache_deception',
                            'extension': ext,
                            'url': test_url,
                            'cached': True
                        })
                    
            except Exception as e:
                if self.verbose:
                    self.log(f"Error: {str(e)}", "ERROR")
    
    def test_vary_header_bypass(self):
        """Test Vary header bypass"""
        self.log("\n" + "="*60, "INFO")
        self.log("Testing Vary Header Bypass", "INFO")
        self.log("="*60, "INFO")
        
        cache_buster = self.generate_cache_buster()
        url = f"{self.target_url}?cb={cache_buster}"
        
        try:
            resp = self.send_request(url)
            if not resp:
                return
            
            vary_header = resp.headers.get('Vary', '')
            
            if vary_header:
                self.log(f"Vary header: {vary_header}", "INFO")
                vary_headers = [h.strip() for h in vary_header.split(',')]
                
                for vary_h in vary_headers:
                    marker = self.generate_unique_marker()
                    resp1 = self.send_request(url, headers={vary_h: marker})
                    if not resp1:
                        continue
                    
                    time.sleep(self.retry_interval)
                    
                    resp2 = self.send_request(url)
                    if not resp2:
                        continue
                    
                    is_cached, _ = self.is_cached(resp2)
                    marker_in_followup = marker in (resp2.text or "")
                    
                    if is_cached and marker_in_followup:
                        self.log(f"[!] Vary header not enforced: {vary_h}", "WARNING")
                        self.results.append({
                            'type': 'vary_bypass',
                            'header': vary_h,
                            'marker': marker
                        })
            else:
                self.log("No Vary header found", "INFO")
                        
        except Exception as e:
            if self.verbose:
                self.log(f"Error: {str(e)}", "ERROR")
    
    def crawl_common_paths(self, base_url: str) -> List[str]:
        """Return common paths that might be cached"""
        paths = [
            "/",
            "/login",
            "/home",
            "/index.html",
            "/index.php",
            "/static/style.css",
            "/static/main.js",
            "/css/style.css",
            "/js/main.js",
            "/images/logo.png",
            "/api/status",
            "/api/config",
            "/assets/app.js",
            "/robots.txt",
            "/sitemap.xml",
            "/favicon.ico"
        ]
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        return [urljoin(base, p) for p in paths]
    
    def test_single_url(self, url: str) -> bool:
        """Test a single URL for cache poisoning - returns True if vulnerable"""
        if self.verbose:
            self.log(f"\nTesting URL: {url}", "INFO")
        
        found_vuln = False
        
        quick_headers = ['X-Forwarded-Host', 'X-Host', 'X-Original-URL']
        payloads = ['evil.example.com', 'injected.test', 'hacker.com']
        
        for header in quick_headers:
            for payload in payloads:
                marker = self.generate_unique_marker()
                combined = f"{payload}/{marker}"
                
                try:
                    resp1 = self.send_request(url, headers={header: combined})
                    if not resp1:
                        continue
                    
                    reflected = marker in (resp1.text or "") or payload in (resp1.text or "")
                    
                    if reflected:
                        time.sleep(self.retry_interval)
                        
                        resp2 = self.send_request(url)
                        if not resp2:
                            continue
                        
                        if marker in (resp2.text or "") or payload in (resp2.text or ""):
                            is_cached, _ = self.is_cached(resp2)
                            if is_cached or self.responses_match(resp1, resp2):
                                self.log(f"[!!!] CACHE POISONING FOUND on {url}", "CRITICAL")
                                self.log(f"     Header: {header} → Payload: {payload}", "CRITICAL")
                                self.results.append({
                                    'vulnerable': True,
                                    'confidence': 'high',
                                    'url': url,
                                    'header': header,
                                    'payload': payload,
                                    'marker': marker
                                })
                                found_vuln = True
                                return True
                            else:
                                self.log(f"[?] Reflection found but not confirmed cached: {header}", "CHECK")
                except Exception as e:
                    if self.verbose:
                        self.log(f"Error testing {url}: {str(e)}", "ERROR")
        
        return found_vuln
    
    def scan_multiple_paths(self, paths: List[str]):
        self.log(f"\n{'='*60}", "INFO")
        self.log(f"Scanning {len(paths)} paths for cache poisoning...", "INFO")
        self.log(f"Using {self.threads} threads", "INFO")
        self.log(f"{'='*60}\n", "INFO")
        
        found_vulnerabilities = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {
                executor.submit(self.test_single_url, url): url 
                for url in paths
            }
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    if future.result():
                        found_vulnerabilities.append(url)
                except Exception as e:
                    self.log(f"Error processing {url}: {str(e)}", "ERROR")
        
        if found_vulnerabilities:
            self.log(f"\n[+] Found vulnerabilities on {len(found_vulnerabilities)} paths:", "SUCCESS")
            for url in found_vulnerabilities:
                print(f"  - {url}")
        else:
            self.log("\n[+] No cache poisoning detected across paths", "INFO")
    
    def run_all_tests(self):
        self.log(f"\nAdvanced Cache Poisoning Scanner", "INFO")
        self.log(f"Target: {self.target_url}", "INFO")
        self.log("="*60 + "\n", "INFO")
        
        self.inspect_caching_configuration(self.target_url)
        
        if not self.get_baseline():
            self.log("Cannot proceed without baseline. Aborting.", "ERROR")
            return
        
        try:
            self.test_unkeyed_headers()
            self.test_host_header_poisoning()
            self.test_query_parameter_injection()
            self.test_path_variations()
            self.test_http_method_override()
            self.test_fat_get_request()
            self.test_header_normalization()
            self.test_response_splitting()
            self.test_vary_header_bypass()
            self.test_cache_deception()
            
            self.print_summary()
                
        except KeyboardInterrupt:
            self.log("\nScan interrupted by user", "WARNING")
        except Exception as e:
            self.log(f"Error during scan: {str(e)}", "ERROR")
            import traceback
            if self.verbose:
                traceback.print_exc()
    
    def print_summary(self):
        """Print scan summary"""
        self.log("\n" + "="*60, "INFO")
        self.log("SCAN COMPLETED", "INFO")
        self.log("="*60, "INFO")
        
        if self.results:
            high_conf = sum(1 for r in self.results if r.get('confidence') == 'high')
            medium_conf = sum(1 for r in self.results if r.get('confidence') == 'medium')
            
            self.log(f"\nFound {len(self.results)} potential vulnerabilities:", "SUCCESS")
            if high_conf > 0:
                self.log(f"  - High Confidence: {high_conf}", "CRITICAL")
            if medium_conf > 0:
                self.log(f"  - Medium Confidence: {medium_conf}", "WARNING")
            
            self.log("\nDetailed Findings:", "INFO")
            for i, result in enumerate(self.results, 1):
                print(f"\n[{i}] {json.dumps(result, indent=2)}")
        else:
            self.log("\nNo vulnerabilities detected.", "INFO")
            self.log("Note: False negatives are common in cache testing.", "WARNING")
        
        self.log("\n" + "="*60, "INFO")
        self.log("MITIGATION RECOMMENDATIONS:", "INFO")
        self.log("="*60, "INFO")
        self.log("1. Ensure cache key includes all user-controllable headers", "INFO")
        self.log("2. Use 'Vary' header to specify which headers affect caching", "INFO")
        self.log("3. Sanitize and validate all input headers", "INFO")
        self.log("4. Avoid reflecting untrusted headers in responses", "INFO")
        self.log("5. Implement proper cache key normalization", "INFO")
        self.log("6. Use 'Cache-Control: private' for user-specific content", "INFO")
        
        self.log("\nReminder: False positives/negatives are possible.", "WARNING")
        self.log("Always verify findings manually from multiple vantage points.", "WARNING")
    
    def save_results(self, filename: str):
        """Save results to JSON file"""
        output = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'baseline_status': self.baseline_response.status_code if self.baseline_response else None,
            'baseline_hash': self.compute_body_hash(self.baseline_response.text) if self.baseline_response else None,
            'total_findings': len(self.results),
            'high_confidence': sum(1 for r in self.results if r.get('confidence') == 'high'),
            'medium_confidence': sum(1 for r in self.results if r.get('confidence') == 'medium'),
            'results': self.results
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        self.log(f"\nResults saved to {filename}", "INFO")


def main():
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║            🕷️  CacheShadow v3.0  🕷️                           ║
    ║         Advanced Web Cache Poisoning Scanner                  ║
    ║         "Exposing the shadows in your cache"                  ║
    ║                                                               ║
    ║  WARNING: Use only on targets you have permission to test!    ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)
    
    parser = argparse.ArgumentParser(
        description='Advanced Web Cache Poisoning Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic single URL scan
  python3 cache_poison_scanner.py -u https://example.com
  
  # Verbose mode with results export
  python3 cache_poison_scanner.py -u https://example.com -v -o results.json
  
  # Scan with custom timing and proxy
  python3 cache_poison_scanner.py -u https://example.com --timeout 15 --delay 2 --proxy http://127.0.0.1:8080
  
  # Crawl and test multiple common paths
  python3 cache_poison_scanner.py -u https://example.com --crawl --threads 5
  
  # Inspect caching configuration only
  python3 cache_poison_scanner.py -u https://example.com --inspect-only

Test Categories:
  ✓ Unkeyed Headers (X-Forwarded-Host, X-Original-URL, Host, etc.)
  ✓ Query Parameter Injection
  ✓ Path Normalization / Variations
  ✓ HTTP Method Override
  ✓ Fat GET Requests (GET with body)
  ✓ Header Normalization Issues
  ✓ HTTP Response Splitting
  ✓ Vary Header Bypass
  ✓ Cache Deception Attacks

Features:
  • Unique marker tracking for accurate detection
  • Response hash comparison for cache confirmation
  • Multiple payload testing for better coverage
  • Confidence scoring (high/medium/low)
  • Multi-threaded path scanning
  • Baseline comparison
  • CDN/cache detection
  • Detailed logging and reporting
  • Proxy support for testing through Burp/ZAP
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', help='Save results to JSON file')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between poison and probe requests (default: 1.0)')
    parser.add_argument('--proxy', help='HTTP proxy (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--threads', type=int, default=2, help='Number of threads for path scanning (default: 2)')
    parser.add_argument('--crawl', action='store_true', help='Crawl and test common paths')
    parser.add_argument('--inspect-only', action='store_true', help='Only inspect caching configuration')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Disable SSL certificate verification')
    
    args = parser.parse_args()
    
    if not args.url.startswith(('http://', 'https://')):
        print("[-] Error: URL must start with http:// or https://")
        sys.exit(1)
    
    scanner = CachePoisoningScanner(
        args.url, 
        verbose=args.verbose,
        timeout=args.timeout,
        retry_interval=args.delay,
        proxy=args.proxy,
        threads=args.threads,
        verify_ssl=not args.no_ssl_verify
    )
    
    if args.inspect_only:
        scanner.inspect_caching_configuration(args.url)
        sys.exit(0)
    
    if args.crawl:
        paths = scanner.crawl_common_paths(args.url)
        scanner.scan_multiple_paths(paths)
    else:
        scanner.run_all_tests()
    
    if args.output:
        scanner.save_results(args.output)


if __name__ == '__main__':
    main()