# Bug Bounty Methodology

## Basic Information Gathering

1. **WHOIS Lookup**
    ```bash
    whois target.com
    ```
    - **Action:** Retrieves WHOIS information for `target.com`, which includes registration details and contact information.

2. **DNS Lookup**
    ```bash
    nslookup target.com
    dig target.com
    ```
    - **Action:** Performs DNS lookups to gather information about the `target.com` domain.

3. **DNS Records for Name Servers and Mail Servers**
    ```bash
    host -t ns target.com
    host -t mx target.com
    ```
    - **Action:** Retrieves DNS records for name servers (NS) and mail servers (MX) for `target.com`.

## Subdomain Enumeration

4. **Subdomain Enumeration with Various Tools**
    ```bash
    sublist3r -d target.com
    amass enum -d target.com
    assetfinder --subs-only target.com
    findomain -t target.com
    ```
    - **Action:** Uses different tools (`sublist3r`, `amass`, `assetfinder`, and `findomain`) to enumerate subdomains for `target.com`.

5. **Mass DNS Resolution**
    ```bash
    massdns -r resolvers.txt -t A -o S -w results.txt -d subdomains.txt
    ```
    - **Action:** Resolves subdomains from `subdomains.txt` using `massdns` and saves results to `results.txt`.

6. **Check Live Subdomains**
    ```bash
    httprobe < subdomains.txt > live_subdomains.txt
    httpx -1 subdomains.txt -o live_hosts.txt
    ```
    - **Action:** Checks which subdomains are live using `httprobe` and `httpx`, and saves the results.

## Scanning and Enumeration

7. **Nmap Scan for Live Hosts**
    ```bash
    nmap -iL live_hosts.txt -oA nmap_scan
    ```
    - **Action:** Performs a full port scan and service detection on live hosts.

8. **Web Technology Fingerprinting**
    ```bash
    whatweb -i live_hosts.txt
    ```
    - **Action:** Identifies technologies used by the web servers of live hosts.

9. **Additional Discovery**
    ```bash
    aquatone-discover -d target.com
    waybackurls target.com | tee waybackurls.txt
    gau target.com | tee gau_urls.txt
    hakrawler -url target.com -depth 2 -plain | tee hakrawler_output.txt
    ```
    - **Action:** Uses `aquatone-discover`, `waybackurls`, `gau`, and `hakrawler` to gather additional URLs and historical data.

10. **Git and Code Repository Searches**
    ```bash
    github-search target.com
    gitrob -repo target.com
    fierce domain target.com
    ```
    - **Action:** Searches GitHub repositories and other code sources for information related to `target.com`.

## Directory and File Brute Forcing

11. **Directory Brute Forcing**
    ```bash
    dirsearch -u target.com -e *
    ```
    - **Action:** Brute-forces directories and files on the target domain.

12. **Advanced Directory and File Brute Forcing**
    ```bash
    ffuf -w wordlist.txt -u https://target.com/FUZZ
    ```
    - **Action:** Uses `ffuf` to perform fuzzing for directories and files with a provided wordlist.

13. **Screenshot Capture**
    ```bash
    gowitness file -f live_hosts.txt -P screenshots/
    ```
    - **Action:** Captures screenshots of live hosts to visualize the web applications.

## Vulnerability Scanning

14. **Nuclei Scanning**
    ```bash
    nuclei -l live_hosts.txt -t templates/
    ```
    - **Action:** Runs Nuclei vulnerability scans on live hosts using the specified templates.

15. **Metadata and File Scanning**
    ```bash
    metabigor net org target.com
    metagoofil -d target.com -t doc,pdf,xls,docx,xlsx,ppt,pptx -l 100
    ```
    - **Action:** Retrieves metadata from files associated with the target domain.

16. **Information Harvesting**
    ```bash
    theHarvester -d target.com -l 500 -b all
    ```
    - **Action:** Gathers information about the target domain from various sources using `theHarvester`.

## DNS and Cloud Enumeration

17. **DNS Enumeration**
    ```bash
    dnsenum target.com
    dnsrecon -d target.com
    shodan search hostname:target.com
    censys search target.com
    ```
    - **Action:** Performs DNS enumeration and searches on Shodan and Censys for additional information.

18. **Advanced Enumeration and Scanning**
    ```bash
    spiderfoot -s target.com -o spiderfoot_report.html
    sniper -t target.com
    ```
    - **Action:** Runs `spiderfoot` and `sniper` for advanced enumeration and scanning.

## Web Application Security Testing

19. **Subdomain Scanning and WAF Detection**
    ```bash
    subfinder -d target.com -o subfinder_results.txt
    wafw00f target.com
    ```
    - **Action:** Uses `subfinder` to discover subdomains and `wafw00f` to detect WAFs.

20. **Parameter and Secret Scanning**
    ```bash
    arjun -u https://target.com -oT arjun_output.txt
    subjack -w subdomains.txt -t 20 -o subjack_results.txt
    ```
    - **Action:** Uses `arjun` to find hidden parameters and `subjack` to check for subdomain takeover vulnerabilities.

21. **Content Discovery and URL Fuzzing**
    ```bash
    meg -d 1000 -v /path/to/live_subdomains.txt
    waymore -u target.com -o waymore_results.txt
    unfurl -u target.com -o unfurl_results.txt
    ```
    - **Action:** Uses `meg`, `waymore`, and `unfurl` for extensive content discovery and URL fuzzing.

22. **XSS and Other Payload Testing**
    ```bash
    dalfox file live_hosts.txt
    gospider -S live_hosts.txt -o gospider_output/
    recon-ng -w workspace -i target.com
    xray webscan --basic-crawler http://target.com
    vhost -u target.com -o vhost_results.txt
    ```
    - **Action:** Scans for XSS and other vulnerabilities using `dalfox`, `gospider`, `recon-ng`, and `xray`.
    - **Action:** Performs virtual host scanning for `target.com` and saves the results to `vhost_results.txt`.

23. **Vhost Scanning**
    ```bash
    vhost -u target.com -o vhost_results.txt
    ```
    - **Action:** Performs virtual host scanning for `target.com` and saves the results to `vhost_results.txt`.

## Payload Generation and Validation

24. **Generate Payloads for Various Attacks**
    ```bash
    gf xss | tee xss_payloads.txt
    gf sqli | tee sqli_payloads.txt
    gf lfi | tee lfi_payloads.txt
    gf ssrf | tee ssrf_payloads.txt
    gf idor | tee idor_payloads.txt
    gf ssti | tee ssti_payloads.txt
    ```
    - **Action:** Uses `gf` to generate and save payloads for various types of attacks.

25. **Git and Secret Scanning**
    ```bash
    git-secrets --scan
    ```
    - **Action:** Scans for secrets in code repositories.

## DNS and Network Scanning

26. **Advanced DNS Scanning and Enumeration**
    ```bash
    shuffledns -d target.com -list resolvers.txt -o shuffledns_results.txt
    dnsgen -f subdomains.txt | massdns -r resolvers.txt -t A -o S -w dnsgen_results.txt
    mapcidr -silent -cidr target.com -o mapcidr_results.txt
    ```
    - **Action:** Uses `shuffledns`, `dnsgen`, and `mapcidr` for advanced DNS and network scanning.

## Additional Scanning and Enumeration

27. **Advanced DNS Scanning with TKO-Subs**
    ```bash
    tko-subs -d target.com -data-providers data.csv
    ```
    - **Action:** Uses `tko-subs` to discover subdomains with additional data providers specified in `data.csv`.

28. **Directory and File Fuzzing with Kiterunner**
    ```bash
    kiterunner -w wordlist.txt -u https://target.com
    ```
    - **Action:** Uses `kiterunner` to perform fuzzing for directories and files on `https://target.com` with the provided `wordlist.txt`.

29. **GitHub Dorking for Sensitive Information**
    ```bash
    github-dorker -d target.com
    ```
    - **Action:** Uses `github-dorker` to find sensitive information related to `target.com` in GitHub repositories.

30. **Redirect Payload Generation with GF**
    ```bash
    gfredirect -u target.com
    ```
    - **Action:** Uses `gfredirect` to generate payloads for testing open redirects on `target.com`.

31. **Parameter Discovery with Paramspider**
    ```bash
    paramspider --domain target.com --output paramspider_output.txt
    ```
    - **Action:** Uses `paramspider` to discover parameters on `target.com` and saves the results to `paramspider_output.txt`.

32. **Directory Brute Forcing with Dirb**
    ```bash
    dirb https://target.com/ -o dirb_output.txt
    ```
    - **Action:** Performs directory brute-forcing on `https://target.com/` with `dirb` and saves the output to `dirb_output.txt`.

33. **WordPress Vulnerability Scanning with WPScan**
    ```bash
    wpscan --url target.com
    ```
    - **Action:** Uses `wpscan` to scan `target.com` for WordPress vulnerabilities.

34. **Cloud Resource Enumeration with Cloud Enum**
    ```bash
    cloud_enum -k target.com -o cloud_enum_output.txt
    ```
    - **Action:** Uses `cloud_enum` to enumerate cloud resources related to `target.com` and saves results to `cloud_enum_output.txt`.

35. **DNS Brute Forcing with Gobuster**
    ```bash
    gobuster dns -d target.com -t 50 -w wordlist.txt
    ```
    - **Action:** Uses `gobuster` for DNS brute-forcing with a specified `wordlist.txt` against `target.com`.

36. **Subdomain Enumeration with Subzero**
    ```bash
    subzero -d target.com
    ```
    - **Action:** Uses `subzero` to discover subdomains for `target.com`.

37. **DNS Walking with DNSWalk**
    ```bash
    dnswalk target.com
    ```
    - **Action:** Performs DNS walking to discover DNS records and potential misconfigurations for `target.com`.

38. **Port Scanning with Masscan**
    ```bash
    masscan -iL live_hosts.txt -p0-65535 -oX masscan_results.xml
    ```
    - **Action:** Uses `masscan` to perform a full port scan on live hosts listed in `live_hosts.txt` and saves the results to `masscan_results.xml`.

39. **Cross-Site Scripting Testing with XSStrike**
    ```bash
    xsstrike -u https://target.com
    ```
    - **Action:** Uses `xsstrike` to test for Cross-Site Scripting (XSS) vulnerabilities on `https://target.com`.

40. **Open Redirect Testing with Byp4xx**
    ```bash
    byp4xx https://target.com/FUZZ
    ```
    - **Action:** Uses `byp4xx` to identify open redirect vulnerabilities by fuzzing endpoints on `https://target.com/FUZZ`.

41. **DNS Resolution with DNSx**
    ```bash
    dnsx -iL subdomains.txt -resp-only -o dnsx_results.txt
    ```
    - **Action:** Uses `dnsx` to resolve subdomains listed in `subdomains.txt` and saves the results to `dnsx_results.txt`.

42. **Wayback Machine Data Collection with Waybackpack**
    ```bash
    waybackpack target.com -d output/
    ```
    - **Action:** Uses `waybackpack` to collect historical data from the Wayback Machine for `target.com` and saves it to `output/`.

43. **PureDNS for Subdomain Resolution**
    ```bash
    puredns resolve subdomains.txt -r resolvers.txt -w puredns_results.txt
    ```
    - **Action:** Uses `puredns` to resolve subdomains from `subdomains.txt` using resolvers in `resolvers.txt` and saves the results to `puredns_results.txt`.

44. **Certificate Transparency Logging with CTFR**
    ```bash
    ctfr -d target.com -o ctfr_results.txt
    ```
    - **Action:** Uses `ctfr` to gather Certificate Transparency logs related to `target.com` and saves results to `ctfr_results.txt`.

45. **DNS Resolver Validation with DNSValidator**
    ```bash
    dnsvalidator -t 100 -f resolvers.txt -o validated_resolvers.txt
    ```
    - **Action:** Uses `dnsvalidator` to validate DNS resolvers listed in `resolvers.txt` and saves the validated resolvers to `validated_resolvers.txt`.

46. **HTTP Check with HTTPX**
    ```bash
    httpx -silent -iL live_subdomains.txt -mc 200 title -tech-detect -o httpx_results.txt
    ```
    - **Action:** Uses `httpx` to perform a silent check on live subdomains listed in `live_subdomains.txt`, filters by HTTP status code 200, detects technologies, and saves results to `httpx_results.txt`.

47. **Cloud Resource Enumeration (Alternative)**
    ```bash
    cloud_enum -k target.com -o cloud_enum_results.txt
    ```
    - **Action:** Uses `cloud_enum` for an alternative method of enumerating cloud resources for `target.com` and saves the results to `cloud_enum_results.txt`.
