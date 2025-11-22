# import requests
# from bs4 import BeautifulSoup
# import re
# import time
# from urllib.parse import urljoin, urlparse
# import threading

# class VulnerabilityScanner:
#     def __init__(self):
#         self.session = requests.Session()
#         self.session.headers.update({
#             'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
#         })
#         self.vulnerabilities = []
#         self.visited_urls = set()
#         self.progress_callback = None

#     def scan(self, target_url, scan_type='full', progress_callback=None):
#         self.progress_callback = progress_callback
#         self.vulnerabilities = []
#         self.visited_urls = set()
        
#         self.update_progress(5, "Initializing scanner...")
        
#         try:
#             # Phase 1: Crawling
#             self.update_progress(10, "Crawling website...", current_url=target_url)
#             self.crawl(target_url)
            
#             total_tests = 0
#             if scan_type in ['full', 'xss']:
#                 total_tests += len(self.xss_payloads)
#             if scan_type in ['full', 'sqli']:
#                 total_tests += len(self.sqli_payloads)
            
#             test_count = 0
            
#             # Phase 2: Vulnerability Testing
#             if scan_type in ['full', 'xss']:
#                 self.update_progress(30, "Testing for XSS vulnerabilities...")
#                 self.test_xss(target_url, test_count, total_tests)
#                 test_count += len(self.xss_payloads)
            
#             if scan_type in ['full', 'sqli']:
#                 self.update_progress(60, "Testing for SQL Injection...")
#                 self.test_sql_injection(target_url, test_count, total_tests)
#                 test_count += len(self.sqli_payloads)
            
#             if scan_type in ['full', 'csrf']:
#                 self.update_progress(80, "Testing for CSRF vulnerabilities...")
#                 self.test_csrf(target_url)
            
#             # Phase 3: Security Headers
#             self.update_progress(90, "Checking security headers...")
#             self.test_security_headers(target_url)
            
#             self.update_progress(100, f"Scan completed! Found {len(self.vulnerabilities)} vulnerabilities", 
#                                vulnerabilities=len(self.vulnerabilities))
            
#         except Exception as e:
#             self.update_progress(0, f"Scan error: {str(e)}", log_message=f"Error: {str(e)}")
#             raise e
        
#         return self.vulnerabilities

#     def update_progress(self, progress, task, vulnerabilities=0, current_url='', log_message=''):
#         if self.progress_callback:
#             self.progress_callback(progress, task, vulnerabilities, current_url, log_message)
#         time.sleep(0.1)  # Smooth progress animation

#     def crawl(self, url, max_pages=20):
#         if len(self.visited_urls) >= max_pages or url in self.visited_urls:
#             return
        
#         self.visited_urls.add(url)
#         self.update_progress(10 + len(self.visited_urls), f"Crawling page {len(self.visited_urls)}", current_url=url)
        
#         try:
#             response = self.session.get(url, timeout=10)
#             soup = BeautifulSoup(response.content, 'html.parser')
            
#             # Extract links
#             for link in soup.find_all('a', href=True):
#                 href = link['href']
#                 full_url = urljoin(url, href)
                
#                 if urlparse(full_url).netloc == urlparse(url).netloc:
#                     self.crawl(full_url, max_pages)
                    
#         except Exception as e:
#             self.update_progress(0, f"Crawling error: {str(e)}", log_message=f"Crawl error: {str(e)}")

#     # ... (other test methods from previous version with progress updates)
#     def test_xss(self, base_url, test_count, total_tests):
#         for i, url in enumerate(list(self.visited_urls)[:5]):
#             self.update_progress(
#                 30 + (i * 10), 
#                 f"XSS testing URL {i+1}/{min(5, len(self.visited_urls))}",
#                 current_url=url
#             )
#             # XSS testing logic here...

#     @property
#     def xss_payloads(self):
#         return [
#             '<script>alert("XSS")</script>',
#             '<img src=x onerror=alert("XSS")>',
#             '<svg onload=alert("XSS")>',
#             '"><script>alert("XSS")</script>',
#             'javascript:alert("XSS")'
#         ]

#     @property
#     def sqli_payloads(self):
#         return [
#             "' OR '1'='1",
#             "' UNION SELECT 1,2,3--",
#             "' AND 1=1--",
#             "' AND 1=2--",
#             "' EXEC xp_cmdshell('dir')--"
#         ]

import requests
from bs4 import BeautifulSoup
import re
import time
from urllib.parse import urljoin, urlparse
import threading

class VulnerabilityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerabilities = []
        self.visited_urls = set()
        
        # Payloads
        self.xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '"><script>alert("XSS")</script>',
            'javascript:alert("XSS")'
        ]
        
        self.sqli_payloads = [
            "' OR '1'='1",
            "' UNION SELECT 1,2,3--",
            "' AND 1=1--",
            "' AND 1=2--",
            "' EXEC xp_cmdshell('dir')--"
        ]

    def scan(self, target_url, scan_type='full', progress_callback=None):
        self.progress_callback = progress_callback
        self.vulnerabilities = []
        self.visited_urls = set()
        
        self.update_progress(5, "Initializing scanner...")
        time.sleep(1)
        
        try:
            # Phase 1: Crawling
            self.update_progress(10, "Crawling website...", current_url=target_url)
            self.crawl(target_url)
            time.sleep(1)
            
            # Phase 2: Vulnerability Testing
            if scan_type in ['full', 'xss']:
                self.update_progress(30, "Testing for XSS vulnerabilities...")
                self.test_xss(target_url)
                time.sleep(1)
            
            if scan_type in ['full', 'sqli']:
                self.update_progress(50, "Testing for SQL Injection...")
                self.test_sql_injection(target_url)
                time.sleep(1)
            
            if scan_type in ['full', 'csrf']:
                self.update_progress(70, "Testing for CSRF vulnerabilities...")
                self.test_csrf(target_url)
                time.sleep(1)
            
            # Phase 3: Security Headers
            self.update_progress(90, "Checking security headers...")
            self.test_security_headers(target_url)
            time.sleep(1)
            
            self.update_progress(100, f"Scan completed! Found {len(self.vulnerabilities)} vulnerabilities", 
                               vulnerabilities=len(self.vulnerabilities))
            
        except Exception as e:
            self.update_progress(0, f"Scan error: {str(e)}", log_message=f"Error: {str(e)}")
            raise e
        
        return self.vulnerabilities

    def update_progress(self, progress, task, vulnerabilities=0, current_url='', log_message=''):
        if self.progress_callback:
            self.progress_callback(progress, task, vulnerabilities, current_url, log_message)

    def crawl(self, url, max_pages=10):
        """Simple crawling to discover URLs"""
        if len(self.visited_urls) >= max_pages or url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        self.update_progress(10 + len(self.visited_urls), f"Crawling page {len(self.visited_urls)}", current_url=url)
        
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract links
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(url, href)
                
                if urlparse(full_url).netloc == urlparse(url).netloc:
                    self.crawl(full_url, max_pages)
                    
        except Exception as e:
            self.log_message(f"Crawl error: {str(e)}")

    def test_xss(self, base_url):
        """Test for XSS vulnerabilities"""
        for url in list(self.visited_urls)[:3]:  # Test first 3 URLs
            try:
                # Test URL parameters
                parsed_url = urlparse(url)
                if parsed_url.query:
                    params = self.parse_query_params(parsed_url.query)
                    for param in params[:2]:  # Test first 2 parameters
                        for payload in self.xss_payloads[:2]:  # Test first 2 payloads
                            test_url = self.inject_payload(url, param, payload)
                            response = self.session.get(test_url, timeout=5)
                            
                            if payload in response.text:
                                self.log_vulnerability(
                                    "Cross-Site Scripting (XSS)",
                                    f"Parameter '{param}' is vulnerable to XSS",
                                    test_url,
                                    "High",
                                    f"Payload: {payload}"
                                )
                                break
            except Exception as e:
                self.log_message(f"XSS test error on {url}: {str(e)}")

    def test_sql_injection(self, base_url):
        """Test for SQL Injection vulnerabilities"""
        for url in list(self.visited_urls)[:3]:
            try:
                parsed_url = urlparse(url)
                if parsed_url.query:
                    params = self.parse_query_params(parsed_url.query)
                    for param in params[:2]:
                        for payload in self.sqli_payloads[:2]:
                            test_url = self.inject_payload(url, param, payload)
                            response = self.session.get(test_url, timeout=5)
                            
                            # Check for SQL error patterns
                            error_patterns = [
                                r"sql.*error",
                                r"warning.*mysql", 
                                r"syntax.*error"
                            ]
                            
                            for pattern in error_patterns:
                                if re.search(pattern, response.text, re.IGNORECASE):
                                    self.log_vulnerability(
                                        "SQL Injection",
                                        f"Parameter '{param}' is vulnerable to SQL Injection",
                                        test_url,
                                        "Critical",
                                        f"Payload: {payload}"
                                    )
                                    break
            except Exception as e:
                self.log_message(f"SQLi test error on {url}: {str(e)}")

    def test_csrf(self, base_url):
        """Test for CSRF vulnerabilities"""
        for url in list(self.visited_urls)[:2]:
            try:
                response = self.session.get(url, timeout=5)
                soup = BeautifulSoup(response.content, 'html.parser')
                
                forms = soup.find_all('form')
                for form in forms[:2]:  # Check first 2 forms
                    # Look for CSRF tokens
                    csrf_inputs = form.find_all('input', {
                        'name': lambda x: x and any(token in x.lower() for token in ['csrf', 'token', 'nonce'])
                    })
                    
                    if not csrf_inputs:
                        self.log_vulnerability(
                            "Cross-Site Request Forgery (CSRF)",
                            "Form missing CSRF protection",
                            url,
                            "Medium",
                            "No CSRF token found in form"
                        )
            except Exception as e:
                self.log_message(f"CSRF test error on {url}: {str(e)}")

    def test_security_headers(self, url):
        """Test for security headers"""
        try:
            response = self.session.get(url, timeout=5)
            headers = response.headers
            
            security_checks = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': None,
                'Content-Security-Policy': None
            }
            
            for header, expected_value in security_checks.items():
                if header not in headers:
                    self.log_vulnerability(
                        "Security Headers Missing",
                        f"Missing security header: {header}",
                        url,
                        "Low",
                        f"Recommended: {expected_value}" if expected_value else "Header should be present"
                    )
        except Exception as e:
            self.log_message(f"Security headers test error: {str(e)}")

    def parse_query_params(self, query_string):
        """Parse query parameters from URL"""
        from urllib.parse import parse_qs
        params = parse_qs(query_string)
        return list(params.keys())

    def inject_payload(self, url, param, payload):
        """Inject payload into URL parameter"""
        from urllib.parse import urlencode, parse_qs, urlparse
        
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        if param in query_params:
            query_params[param] = [payload]
        
        new_query = urlencode(query_params, doseq=True)
        return parsed._replace(query=new_query).geturl()

    def log_vulnerability(self, vuln_type, description, url, severity, evidence=None):
        """Log discovered vulnerability"""
        vulnerability = {
            'type': vuln_type,
            'description': description,
            'url': url,
            'severity': severity,
            'evidence': evidence,
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        if vulnerability not in self.vulnerabilities:
            self.vulnerabilities.append(vulnerability)
            self.log_message(f"[{severity}] {vuln_type}: {description}")

    def log_message(self, message):
        """Helper method to log messages"""
        if hasattr(self, 'progress_callback') and self.progress_callback:
            timestamp = time.strftime("%H:%M:%S")
            self.progress_callback(
                getattr(self, 'current_progress', 0),
                getattr(self, 'current_task', ''),
                len(self.vulnerabilities),
                getattr(self, 'current_url', ''),
                f"[{timestamp}] {message}"
            )