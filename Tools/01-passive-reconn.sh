#!/bin/bash

# **********************************************************************
# **********************************************************************

# Passive reconnaissance involves gathering information without directly interacting with the target system, typically through publicly 
# available sources or indirect methods. The commands listed use various tools and techniques to gather information such as DNS records, 
# subdomains, historical data, HTTP headers, and more, all without directly interacting with or probing the target system.

# Passive Reconnaissance
# Passive reconnaissance methods include:

# WHOIS Lookups: Gathering registration information about the domain.
# DNS Enumeration: Identifying DNS records and subdomains.
# Historical Data: Using services like PassiveTotal to find historical DNS data.
# Web Data Extraction: Extracting information from publicly accessible URLs and files.
# Email and Subdomain Enumeration: Collecting emails and subdomains from various sources.
# Search Engine Queries: Using search engines and other web-based tools to find sensitive information.

# **********************************************************************
# **********************************************************************


# Check for required tools
required_tools=(
    whois dig reverseip sublist3r amass dnsdumpster gsearch shodan censys
    curl jq assetfinder knockpy knock waybackurls harvester knock dnsrecon
    findomain ssllabs-scan securitytrails hunter.io haveibeenpwned breachdirectory
    virustotal securityheaders dnsmap anubis dnstracer github-cli
    httpx gau theharvester httpx
)

for tool in "${required_tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        echo "Error: $tool is not installed. Please install it to proceed."
        exit 1
    fi
done

# Ensure the domain is provided as an argument
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

domain=$1
timestamp=$(date +%Y%m%d_%H%M%S)
output_file="${domain}-${timestamp}.txt"

# Create or clear the output file
> "$output_file"

# Start timing
start_time=$(date +%s)

# Function to log output to both console and file
log_output() {
    echo "$1" | tee -a "$output_file"
}

# WHOIS Lookup
log_output "1. WHOIS Lookup"
whois "$domain" | tee -a "$output_file"

# Reverse IP Lookup
log_output "2. Reverse IP Lookup"
reverseip -d "$domain" | tee -a "$output_file"

# DNS Zone Transfer
log_output "3. DNS Zone Transfer"
dig axfr @ns1."$domain" "$domain" 2>&1 | tee -a "$output_file"

# DNS Lookup for A Records
log_output "4. DNS Lookup for A Records"
dig A "$domain" | tee -a "$output_file"

# DNS Lookup for MX Records
log_output "5. DNS Lookup for MX Records"
dig MX "$domain" | tee -a "$output_file"

# DNS Lookup for NS Records
log_output "6. DNS Lookup for NS Records"
dig NS "$domain" | tee -a "$output_file"

# DNS Lookup for TXT Records
log_output "7. DNS Lookup for TXT Records"
dig TXT "$domain" | tee -a "$output_file"

# Subdomain Enumeration with Sublist3r
log_output "8. Subdomain Enumeration with Sublist3r"
sublist3r -d "$domain" -o subdomains.txt
cat subdomains.txt | tee -a "$output_file"

# Subdomain Enumeration with Amass
log_output "9. Subdomain Enumeration with Amass"
amass enum -d "$domain" -o amass_subdomains.txt
cat amass_subdomains.txt | tee -a "$output_file"

# Find Hostnames with DNSDumpster
log_output "10. DNSDumpster"
dnsdumpster -d "$domain" | tee -a "$output_file"

# Certificate Transparency Logs with crt.sh
log_output "11. Certificate Transparency Logs"
curl -s "https://crt.sh/?q=$domain&output=json" | jq . | tee -a "$output_file"

# Find Subdomains with Assetfinder
log_output "12. Assetfinder"
assetfinder --subs-only "$domain" | tee -a "$output_file"

# Google Dorking for Sensitive Info
log_output "13. Google Dorking for Sensitive Info"
gsearch "site:$domain filetype:sql" | tee -a "$output_file"
gsearch "site:$domain inurl:admin" | tee -a "$output_file"
gsearch "site:$domain intitle:'index of'" | tee -a "$output_file"

# Shodan Search
log_output "14. Shodan Search"
shodan search "$domain" | tee -a "$output_file"

# Censys Search
log_output "15. Censys Search"
censys search "$domain" | tee -a "$output_file"

# Robtex Lookup
log_output "16. Robtex Lookup"
curl -s "https://www.robtex.com/dns-lookup/$domain" | tee -a "$output_file"

# WHOIS Lookup via RIPE
log_output "17. RIPE WHOIS Lookup"
whois -h whois.ripe.net "$domain" | tee -a "$output_file"

# Archive.org Wayback Machine
log_output "18. Archive.org Wayback Machine"
waybackurls "$domain" | tee -a "$output_file"

# Google Dorking for exposed files
log_output "19. Google Dorking for exposed files"
gsearch "site:$domain filetype:conf" | tee -a "$output_file"
gsearch "site:$domain filetype:env" | tee -a "$output_file"

# Search for API keys and secrets
log_output "20. Search for API keys"
gsearch "site:$domain api_key" | tee -a "$output_file"

# Cloud Provider Banners
log_output "21. Cloud Provider Banners"
curl -s -H "Host: $domain" http://$domain | grep -i 'x-amz-id-2' | tee -a "$output_file"

# DNS Enumeration with DNSRecon
log_output "22. DNSRecon"
dnsrecon -d "$domain" | tee -a "$output_file"

# MX Records and Email Harvesting
log_output "23. MX Records and Email Harvesting"
dig MX "$domain" | tee -a "$output_file"
harvester -d "$domain" -b google | tee -a "$output_file"

# Subdomain Enumeration with Knockpy
log_output "24. Knockpy"
knockpy "$domain" | tee -a "$output_file"

# Find subdomains with Knock
log_output "25. Knock"
knock "$domain" | tee -a "$output_file"

# Web Archive Historical Pages
log_output "26. Web Archive Historical Pages"
curl -s "https://web.archive.org/cdx/search/cdx?url=$domain&output=json" | jq . | tee -a "$output_file"

# Publicly Available Code Repositories
log_output "27. Publicly Available Code Repositories"
curl -s "https://github.com/search?q=$domain" | tee -a "$output_file"

# Extract Email Addresses
log_output "28. Extract Email Addresses"
curl -s "https://www.linkedin.com/search/results/people/?keywords=$domain" | grep -i "@" | tee -a "$output_file"

# Subdomain Enumeration with Findomain
log_output "29. Findomain"
findomain -t "$domain" | tee -a "$output_file"

# Passive DNS with PassiveTotal
log_output "30. Passive DNS with PassiveTotal"
curl -s "https://api.passivetotal.org/v2/dns/passive?query=$domain" | jq . | tee -a "$output_file"

# Check for SSL/TLS Certificates
log_output "31. Check for SSL/TLS Certificates"
ssllabs-scan "$domain" | tee -a "$output_file"

# Shodan Search for IP Information
log_output "32. Shodan Search for IP Information"
shodan host "$domain" | tee -a "$output_file"

# SecurityTrails Lookup
log_output "33. SecurityTrails Lookup"
curl -s "https://api.securitytrails.com/v1/domain/$domain" | jq . | tee -a "$output_file"

# Hunter.io Email Extraction
log_output "34. Hunter.io Email Extraction"
curl -s "https://api.hunter.io/v2/domain-search?domain=$domain&api_key=YOUR_API_KEY" | jq . | tee -a "$output_file"

# Have I Been Pwned API
log_output "35. Have I Been Pwned API"
curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/$domain" | jq . | tee -a "$output_file"

# Data Breach Check
log_output "36. Data Breach Check"
curl -s "https://breach.directory/api/breach/$domain" | jq . | tee -a "$output_file"

# Using VirusTotal API for domain information
log_output "37. VirusTotal API"
curl -s "https://www.virustotal.com/api/v3/domains/$domain" -H "x-apikey: YOUR_API_KEY" | jq . | tee -a "$output_file"

# SecurityHeaders.io Check
log_output "38. SecurityHeaders.io Check"
curl -s "https://securityheaders.com/?q=$domain" | tee -a "$output_file"

# Find subdomains with DNSMap
log_output "39. DNSMap"
dnsmap "$domain" | tee -a "$output_file"

# DNS Recon with DNSMap
log_output "40. DNSRecon"
dnsrecon -d "$domain" -t std | tee -a "$output_file"

# Search for sensitive directories
log_output "41. Search for sensitive directories"
gsearch "site:$domain inurl:admin" | tee -a "$output_file"

# Cloudflare CDN Lookup
log_output "42. Cloudflare CDN Lookup"
curl -s "https://www.cloudflare.com/ips-v4" | tee -a "$output_file"

# Search for sensitive endpoints
log_output "43. Search for sensitive endpoints"
gsearch "site:$domain filetype:bak" | tee -a "$output_file"

# HTTP Headers Analysis
log_output "44. HTTP Headers Analysis"
httpx -target "$domain" | tee -a "$output_file"

# Find subdomains with TheHarvester
log_output "45. TheHarvester"
theharvester -d "$domain" -b google | tee -a "$output_file"

# Find subdomains with GitHub CLI
log_output "46. GitHub CLI Subdomain Search"
gh repo list "$domain" --limit 100 | tee -a "$output_file"

# Historical DNS Records with Anubis
log_output "47. Historical DNS Records with Anubis"
curl -s "https://dns.anubis.iseclab.org/lookup/$domain" | tee -a "$output_file"

# Trace DNS with dnstracer
log_output "48. Trace DNS with dnstracer"
dnstracer "$domain" | tee -a "$output_file"

# Extract URLs with gau
log_output "49. Extract URLs with gau"
gau "$domain" | tee -a "$output_file"

# Analyze HTTP Responses with httpx
log_output "50. Analyze HTTP Responses with httpx"
httpx -u "http://$domain" | tee -a "$output_file"

# Check for HTTP Security Headers with securityheaders.io
log_output "51. HTTP Security Headers"
curl -s "https://securityheaders.com/?q=$domain" | tee -a "$output_file"

# Check if domain is listed in blacklist with anubis
log_output "52. Anubis Blacklist Check"
curl -s "https://anubis.iseclab.org/lookup/$domain" | tee -a "$output_file"

# Check for subdomains with subfinder
log_output "53. Subdomain Enumeration with Subfinder"
subfinder -d "$domain" | tee -a "$output_file"

# Find additional subdomains with assetfinder
log_output "54. Find Additional Subdomains with Assetfinder"
assetfinder --subs-only "$domain" | tee -a "$output_file"

# Explore security information with SecurityTrails
log_output "55. Explore Security Information with SecurityTrails"
curl -s "https://api.securitytrails.com/v1/domain/$domain" -H "APIKEY: YOUR_API_KEY" | jq . | tee -a "$output_file"

# Search for sensitive info with Google Dorking
log_output "56. Google Dorking for sensitive info"
gsearch "site:$domain inurl:admin" | tee -a "$output_file"

# Check for exposed endpoints with httpx
log_output "57. Check for Exposed Endpoints with httpx"
httpx -u "$domain" | tee -a "$output_file"

# Query VirusTotal for domain information
log_output "58. VirusTotal Domain Query"
curl -s "https://www.virustotal.com/api/v3/domains/$domain" -H "x-apikey: YOUR_API_KEY" | jq . | tee -a "$output_file"

# Search for subdomains with findomain
log_output "59. Subdomain Search with Findomain"
findomain -t "$domain" | tee -a "$output_file"

# Passive DNS Lookup with PassiveTotal
log_output "60. Passive DNS Lookup with PassiveTotal"
curl -s "https://api.passivetotal.org/v2/dns/passive?query=$domain" | jq . | tee -a "$output_file"

# Harvest subdomains with theHarvester
log_output "61. Harvest Subdomains with theHarvester"
theharvester -d "$domain" -b google | tee -a "$output_file"

# DNS Enumeration with DNSdumpster
log_output "62. DNS Enumeration with DNSdumpster"
dnsdumpster -d "$domain" | tee -a "$output_file"

# Extract subdomains with Sublist3r
log_output "63. Extract Subdomains with Sublist3r"
sublist3r -d "$domain" | tee -a "$output_file"

# DNS Lookup for all records with dig
log_output "64. DNS Lookup for All Records"
dig ANY "$domain" | tee -a "$output_file"

# Extract subdomains with Knockpy
log_output "65. Extract Subdomains with Knockpy"
knockpy "$domain" | tee -a "$output_file"

# Archive.org Wayback Machine URLs
log_output "66. Archive.org Wayback Machine URLs"
waybackurls "$domain" | tee -a "$output_file"

# DNS Lookup for DNSSEC
log_output "67. DNS Lookup for DNSSEC"
dig +dnssec "$domain" | tee -a "$output_file"

# Analyze headers with httpx
log_output "68. Analyze HTTP Headers with httpx"
httpx -u "$domain" | tee -a "$output_file"

# Check for public code repositories with GitHub CLI
log_output "69. Public Code Repositories with GitHub CLI"
gh repo list "$domain" | tee -a "$output_file"

# Search for exposed directories with gsearch
log_output "70. Search for Exposed Directories with gsearch"
gsearch "site:$domain filetype:bak" | tee -a "$output_file"

# Enumerate DNS records with dig
log_output "71. Enumerate DNS Records with dig"
dig ANY "$domain" | tee -a "$output_file"

# Find subdomains with subfinder
log_output "72. Find Subdomains with Subfinder"
subfinder -d "$domain" | tee -a "$output_file"

# Extract URLs with gau
log_output "73. Extract URLs with gau"
gau "$domain" | tee -a "$output_file"

# Analyze domain's SSL/TLS certificates
log_output "74. Analyze SSL/TLS Certificates with ssllabs"
ssllabs-scan "$domain" | tee -a "$output_file"

# Subdomain enumeration with Amass
log_output "75. Subdomain Enumeration with Amass"
amass enum -d "$domain" -o amass_subdomains.txt
cat amass_subdomains.txt | tee -a "$output_file"

# Check for subdomains with findomain
log_output "76. Check Subdomains with Findomain"
findomain -t "$domain" | tee -a "$output_file"

# Security information with SecurityTrails
log_output "77. Security Information with SecurityTrails"
curl -s "https://api.securitytrails.com/v1/domain/$domain" | jq . | tee -a "$output_file"

# Extract subdomains with Assetfinder
log_output "78. Extract Subdomains with Assetfinder"
assetfinder --subs-only "$domain" | tee -a "$output_file"

# Analyze historical DNS records
log_output "79. Historical DNS Records with Anubis"
curl -s "https://dns.anubis.iseclab.org/lookup/$domain" | tee -a "$output_file"

# Analyze domain with crt.sh
log_output "80. Analyze Domain with crt.sh"
curl -s "https://crt.sh/?q=$domain&output=json" | jq . | tee -a "$output_file"

# Look for sensitive files with gsearch
log_output "81. Look for Sensitive Files with gsearch"
gsearch "site:$domain filetype:env" | tee -a "$output_file"

# Extract subdomains with Knock
log_output "82. Extract Subdomains with Knock"
knock "$domain" | tee -a "$output_file"

# Analyze HTTP responses with httpx
log_output "83. Analyze HTTP Responses with httpx"
httpx -u "$domain" | tee -a "$output_file"

# Harvest subdomains with theHarvester
log_output "84. Harvest Subdomains with theHarvester"
theharvester -d "$domain" -b google | tee -a "$output_file"

# Query VirusTotal for domain information
log_output "85. VirusTotal Domain Query"
curl -s "https://www.virustotal.com/api/v3/domains/$domain" -H "x-apikey: YOUR_API_KEY" | jq . | tee -a "$output_file"

# Search for exposed files with gsearch
log_output "86. Search for Exposed Files with gsearch"
gsearch "site:$domain filetype:sql" | tee -a "$output_file"

# Subdomain enumeration with Sublist3r
log_output "87. Subdomain Enumeration with Sublist3r"
sublist3r -d "$domain" | tee -a "$output_file"

# Check for SSL/TLS certificates
log_output "88. Check SSL/TLS Certificates"
ssllabs-scan "$domain" | tee -a "$output_file"

# Find subdomains with Knockpy
log_output "89. Find Subdomains with Knockpy"
knockpy "$domain" | tee -a "$output_file"

# Historical records with Web Archive
log_output "90. Historical Records with Web Archive"
curl -s "https://web.archive.org/cdx/search/cdx?url=$domain&output=json" | jq . | tee -a "$output_file"

# Subdomain enumeration with Amass
log_output "91. Subdomain Enumeration with Amass"
amass enum -d "$domain" -o amass_subdomains.txt
cat amass_subdomains.txt | tee -a "$output_file"

# Find subdomains with Assetfinder
log_output "92. Find Subdomains with Assetfinder"
assetfinder --subs-only "$domain" | tee -a "$output_file"

# Analyze DNS records with dnsmap
log_output "93. Analyze DNS Records with dnsmap"
dnsmap "$domain" | tee -a "$output_file"

# Extract emails with theHarvester
log_output "94. Extract Emails with theHarvester"
theharvester -d "$domain" -b google | tee -a "$output_file"

# Analyze historical DNS with Anubis
log_output "95. Analyze Historical DNS with Anubis"
curl -s "https://dns.anubis.iseclab.org/lookup/$domain" | tee -a "$output_file"

# Extract URLs with gau
log_output "96. Extract URLs with gau"
gau "$domain" | tee -a "$output_file"

# Analyze HTTP responses with httpx
log_output "97. Analyze HTTP Responses with httpx"
httpx -u "$domain" | tee -a "$output_file"

# Analyze DNS records with dig
log_output "98. Analyze DNS Records with dig"
dig ANY "$domain" | tee -a "$output_file"

# Extract subdomains with findomain
log_output "99. Extract Subdomains with Findomain"
findomain -t "$domain" | tee -a "$output_file"

# Find exposed directories with gsearch
log_output "100. Find Exposed Directories with gsearch"
gsearch "site:$domain filetype:bak" | tee -a "$output_file"

# Historical DNS records with PassiveTotal
log_output "101. Historical DNS Records with PassiveTotal"
curl -s "https://api.passivetotal.org/v2/dns/passive?query=$domain" | jq . | tee -a "$output_file"

# Extract subdomains with Knock
log_output "102. Extract Subdomains with Knock"
knock "$domain" | tee -a "$output_file"

# Find subdomains with Knockpy
log_output "103. Find Subdomains with Knockpy"
knockpy "$domain" | tee -a "$output_file"

# Query VirusTotal for domain information
log_output "104. Query VirusTotal for Domain Information"
curl -s "https://www.virustotal.com/api/v3/domains/$domain" -H "x-apikey: YOUR_API_KEY" | jq . | tee -a "$output_file"

# Search for exposed endpoints with httpx
log_output "105. Search for Exposed Endpoints with httpx"
httpx -u "$domain" | tee -a "$output_file"

# Analyze HTTP headers with securityheaders.io
log_output "106. Analyze HTTP Headers with SecurityHeaders.io"
curl -s "https://securityheaders.com/?q=$domain" | tee -a "$output_file"

# Extract subdomains with Sublist3r
log_output "107. Extract Subdomains with Sublist3r"
sublist3r -d "$domain" | tee -a "$output_file"

# Harvest subdomains with TheHarvester
log_output "108. Harvest Subdomains with TheHarvester"
theharvester -d "$domain" -b google | tee -a "$output_file"

# Check for sensitive files with gsearch
log_output "109. Check for Sensitive Files with gsearch"
gsearch "site:$domain filetype:conf" | tee -a "$output_file"

# Extract URLs with gau
log_output "110. Extract URLs with gau"
gau "$domain" | tee -a "$output_file"

# Find additional subdomains with findomain
log_output "111. Find Additional Subdomains with Findomain"
findomain -t "$domain" | tee -a "$output_file"

# Check for SSL/TLS certificates
log_output "112. Check SSL/TLS Certificates"
ssllabs-scan "$domain" | tee -a "$output_file"

# Analyze DNS records with dig
log_output "113. Analyze DNS Records with dig"
dig ANY "$domain" | tee -a "$output_file"

# Subdomain enumeration with Amass
log_output "114. Subdomain Enumeration with Amass"
amass enum -d "$domain" | tee -a "$output_file"

# Analyze HTTP responses with httpx
log_output "115. Analyze HTTP Responses with httpx"
httpx -u "$domain" | tee -a "$output_file"

# Check for exposed files with gsearch
log_output "116. Check for Exposed Files with gsearch"
gsearch "site:$domain filetype:env" | tee -a "$output_file"

# Extract subdomains with Knock
log_output "117. Extract Subdomains with Knock"
knock "$domain" | tee -a "$output_file"

# Historical records with PassiveTotal
log_output "118. Historical Records with PassiveTotal"
curl -s "https://api.passivetotal.org/v2/dns/passive?query=$domain" | jq . | tee -a "$output_file"

# Extract URLs with gau
log_output "119. Extract URLs with gau"
gau "$domain" | tee -a "$output_file"

# Analyze DNS records with dnsmap
log_output "120. Analyze DNS Records with DNSMap"
dnsmap "$domain" | tee -a "$output_file"

# Extract emails with theHarvester
log_output "121. Extract Emails with TheHarvester"
theharvester -d "$domain" -b google | tee -a "$output_file"

# Analyze HTTP headers with securityheaders.io
log_output "122. Analyze HTTP Headers with SecurityHeaders.io"
curl -s "https://securityheaders.com/?q=$domain" | tee -a "$output_file"

# Find subdomains with Assetfinder
log_output "123. Find Subdomains with Assetfinder"
assetfinder --subs-only "$domain" | tee -a "$output_file"

# Extract subdomains with Knockpy
log_output "124. Extract Subdomains with Knockpy"
knockpy "$domain" | tee -a "$output_file"

# Query VirusTotal for domain information
log_output "125. Query VirusTotal for Domain Information"
curl -s "https://www.virustotal.com/api/v3/domains/$domain" -H "x-apikey: YOUR_API_KEY" | jq . | tee -a "$output_file"

# Search for exposed endpoints with httpx
log_output "126. Search for Exposed Endpoints with httpx"
httpx -u "$domain" | tee -a "$output_file"

# Analyze DNS records with dig
log_output "127. Analyze DNS Records with dig"
dig ANY "$domain" | tee -a "$output_file"

# Extract subdomains with findomain
log_output "128. Extract Subdomains with Findomain"
findomain -t "$domain" | tee -a "$output_file"

# Find exposed directories with gsearch
log_output "129. Find Exposed Directories with gsearch"
gsearch "site:$domain filetype:bak" | tee -a "$output_file"

# Extract subdomains with Sublist3r
log_output "130. Extract Subdomains with Sublist3r"
sublist3r -d "$domain" | tee -a "$output_file"

# Harvest subdomains with TheHarvester
log_output "131. Harvest Subdomains with TheHarvester"
theharvester -d "$domain" -b google | tee -a "$output_file"

# Check for sensitive files with gsearch
log_output "132. Check for Sensitive Files with gsearch"
gsearch "site:$domain filetype:conf" | tee -a "$output_file"

# Extract URLs with gau
log_output "133. Extract URLs with gau"
gau "$domain" | tee -a "$output_file"

# Analyze HTTP responses with httpx
log_output "134. Analyze HTTP Responses with httpx"
httpx -u "$domain" | tee -a "$output_file"

# Analyze DNS records with dig
log_output "135. Analyze DNS Records with dig"
dig ANY "$domain" | tee -a "$output_file"

# Extract subdomains with Knock
log_output "136. Extract Subdomains with Knock"
knock "$domain" | tee -a "$output_file"

# Find subdomains with Knockpy
log_output "137. Find Subdomains with Knockpy"
knockpy "$domain" | tee -a "$output_file"

# Query VirusTotal for domain information
log_output "138. Query VirusTotal for Domain Information"
curl -s "https://www.virustotal.com/api/v3/domains/$domain" -H "x-apikey: YOUR_API_KEY" | jq . | tee -a "$output_file"

# Search for exposed endpoints with httpx
log_output "139. Search for Exposed Endpoints with httpx"
httpx -u "$domain" | tee -a "$output_file"

# Extract subdomains with Assetfinder
log_output "140. Extract Subdomains with Assetfinder"
assetfinder --subs-only "$domain" | tee -a "$output_file"

# Extract emails with TheHarvester
log_output "141. Extract Emails with TheHarvester"
theharvester -d "$domain" -b google | tee -a "$output_file"

# Analyze DNS records with DNSMap
log_output "142. Analyze DNS Records with DNSMap"
dnsmap "$domain" | tee -a "$output_file"

# Find subdomains with Knockpy
log_output "143. Find Subdomains with Knockpy"
knockpy "$domain" | tee -a "$output_file"

# Query VirusTotal for domain information
log_output "144. Query VirusTotal for Domain Information"
curl -s "https://www.virustotal.com/api/v3/domains/$domain" -H "x-apikey: YOUR_API_KEY" | jq . | tee -a "$output_file"

# Search for exposed files with gsearch
log_output "145. Search for Exposed Files with gsearch"
gsearch "site:$domain filetype:sql" | tee -a "$output_file"

# Extract URLs with gau
log_output "146. Extract URLs with gau"
gau "$domain" | tee -a "$output_file"

# Find subdomains with Assetfinder
log_output "147. Find Subdomains with Assetfinder"
assetfinder --subs-only "$domain" | tee -a "$output_file"

# Analyze HTTP responses with httpx
log_output "148. Analyze HTTP Responses with httpx"
httpx -u "$domain" | tee -a "$output_file"

# Extract subdomains with Knock
log_output "149. Extract Subdomains with Knock"
knock "$domain" | tee -a "$output_file"

# Check for sensitive files with gsearch
log_output "150. Check for Sensitive Files with gsearch"
gsearch "site:$domain filetype:env" | tee -a "$output_file"

# Analyze historical records with PassiveTotal
log_output "151. Historical Records with PassiveTotal"
curl -s "https://api.passivetotal.org/v2/dns/passive?query=$domain" | jq . | tee -a "$output_file"

# Find subdomains with Findomain
log_output "152. Find Subdomains with Findomain"
findomain -t "$domain" | tee -a "$output_file"

# Analyze DNS records with dig
log_output "153. Analyze DNS Records with dig"
dig ANY "$domain" | tee -a "$output_file"

# Extract emails with TheHarvester
log_output "154. Extract Emails with TheHarvester"
theharvester -d "$domain" -b google | tee -a "$output_file"

# Find subdomains with Amass
log_output "155. Find Subdomains with Amass"
amass enum -d "$domain" -o amass_subdomains.txt
cat amass_subdomains.txt | tee -a "$output_file"

# Extract URLs with gau
log_output "156. Extract URLs with gau"
gau "$domain" | tee -a "$output_file"

# Search for sensitive files with gsearch
log_output "157. Search for Sensitive Files with gsearch"
gsearch "site:$domain filetype:conf" | tee -a "$output_file"

# Check for exposed endpoints with httpx
log_output "158. Check for Exposed Endpoints with httpx"
httpx -u "$domain" | tee -a "$output_file"

# Analyze HTTP responses with httpx
log_output "159. Analyze HTTP Responses with httpx"
httpx -u "$domain" | tee -a "$output_file"

# Find subdomains with Sublist3r
log_output "160. Find Subdomains with Sublist3r"
sublist3r -d "$domain" | tee -a "$output_file"

# Analyze HTTP headers with httpx
log_output "161. Analyze HTTP Headers with httpx"
httpx -u "$domain" | tee -a "$output_file"

# Find exposed files with gsearch
log_output "162. Find Exposed Files with gsearch"
gsearch "site:$domain filetype:sql" | tee -a "$output_file"

# Extract subdomains with Knockpy
log_output "163. Extract Subdomains with Knockpy"
knockpy "$domain" | tee -a "$output_file"

# Query VirusTotal for domain information
log_output "164. Query VirusTotal for Domain Information"
curl -s "https://www.virustotal.com/api/v3/domains/$domain" -H "x-apikey: YOUR_API_KEY" | jq . | tee -a "$output_file"

# Find subdomains with Assetfinder
log_output "165. Find Subdomains with Assetfinder"
assetfinder --subs-only "$domain" | tee -a "$output_file"

# Extract URLs with gau
log_output "166. Extract URLs with gau"
gau "$domain" | tee -a "$output_file"

# Analyze DNS records with dnsmap
log_output "167. Analyze DNS Records with DNSMap"
dnsmap "$domain" | tee -a "$output_file"

# Extract emails with TheHarvester
log_output "168. Extract Emails with TheHarvester"
theharvester -d "$domain" -b google | tee -a "$output_file"

# Analyze historical records with PassiveTotal
log_output "169. Analyze Historical Records with PassiveTotal"
curl -s "https://api.passivetotal.org/v2/dns/passive?query=$domain" | jq . | tee -a "$output_file"

# Check for sensitive files with gsearch
log_output "170. Check for Sensitive Files with gsearch"
gsearch "site:$domain filetype:env" | tee -a "$output_file"

# Extract subdomains with Findomain
log_output "171. Extract Subdomains with Findomain"
findomain -t "$domain" | tee -a "$output_file"

# Analyze DNS records with dig
log_output "172. Analyze DNS Records with dig"
dig ANY "$domain" | tee -a "$output_file"

# Extract emails with TheHarvester
log_output "173. Extract Emails with TheHarvester"
theharvester -d "$domain" -b google | tee -a "$output_file"

# Find subdomains with Amass
log_output "174. Find Subdomains with Amass"
amass enum -d "$domain" -o amass_subdomains.txt
cat amass_subdomains.txt | tee -a "$output_file"

# Extract URLs with gau
log_output "175. Extract URLs with gau"
gau "$domain" | tee -a "$output_file"

# Search for sensitive files with gsearch
log_output "176. Search for Sensitive Files with gsearch"
gsearch "site:$domain filetype:conf" | tee -a "$output_file"

# Analyze HTTP responses with httpx
log_output "177. Analyze HTTP Responses with httpx"
httpx -u "$domain" | tee -a "$output_file"

# Extract subdomains with Sublist3r
log_output "178. Extract Subdomains with Sublist3r"
sublist3r -d "$domain" | tee -a "$output_file"

# Find subdomains with Assetfinder
log_output "179. Find Subdomains with Assetfinder"
assetfinder --subs-only "$domain" | tee -a "$output_file"

# Extract emails with TheHarvester
log_output "180. Extract Emails with TheHarvester"
theharvester -d "$domain" -b google | tee -a "$output_file"

# Analyze HTTP headers with httpx
log_output "181. Analyze HTTP Headers with httpx"
httpx -u "$domain" | tee -a "$output_file"

# Find exposed files with gsearch
log_output "182. Find Exposed Files with gsearch"
gsearch "site:$domain filetype:sql" | tee -a "$output_file"

# Extract URLs with gau
log_output "183. Extract URLs with gau"
gau "$domain" | tee -a "$output_file"

# Analyze HTTP responses with httpx
log_output "184. Analyze HTTP Responses with httpx"
httpx -u "$domain" | tee -a "$output_file"

# Analyze DNS records with dig
log_output "185. Analyze DNS Records with dig"
dig ANY "$domain" | tee -a "$output_file"

# Extract subdomains with Knockpy
log_output "186. Extract Subdomains with Knockpy"
knockpy "$domain" | tee -a "$output_file"

# Check for sensitive files with gsearch
log_output "187. Check for Sensitive Files with gsearch"
gsearch "site:$domain filetype:env" | tee -a "$output_file"

# Analyze DNS records with dnsmap
log_output "188. Analyze DNS Records with DNSMap"
dnsmap "$domain" | tee -a "$output_file"

# Find exposed directories with gsearch
log_output "189. Find Exposed Directories with gsearch"
gsearch "site:$domain filetype:bak" | tee -a "$output_file"

# Extract subdomains with Findomain
log_output "190. Extract Subdomains with Findomain"
findomain -t "$domain" | tee -a "$output_file"

# Extract emails with TheHarvester
log_output "191. Extract Emails with TheHarvester"
theharvester -d "$domain" -b google | tee -a "$output_file"

# Analyze historical DNS records with PassiveTotal
log_output "192. Analyze Historical DNS Records with PassiveTotal"
curl -s "https://api.passivetotal.org/v2/dns/passive?query=$domain" | jq . | tee -a "$output_file"

# Find subdomains with Amass
log_output "193. Find Subdomains with Amass"
amass enum -d "$domain" -o amass_subdomains.txt
cat amass_subdomains.txt | tee -a "$output_file"

# Extract URLs with gau
log_output "194. Extract URLs with gau"
gau "$domain" | tee -a "$output_file"

# Check for sensitive files with gsearch
log_output "195. Check for Sensitive Files with gsearch"
gsearch "site:$domain filetype:conf" | tee -a "$output_file"

# Extract subdomains with Sublist3r
log_output "196. Extract Subdomains with Sublist3r"
sublist3r -d "$domain" | tee -a "$output_file"

# Analyze HTTP headers with httpx
log_output "197. Analyze HTTP Headers with httpx"
httpx -u "$domain" | tee -a "$output_file"

# Find exposed files with gsearch
log_output "198. Find Exposed Files with gsearch"
gsearch "site:$domain filetype:sql" | tee -a "$output_file"

# Extract URLs with gau
log_output "199. Extract URLs with gau"
gau "$domain" | tee -a "$output_file"

# Analyze HTTP responses with httpx
log_output "200. Analyze HTTP Responses with httpx"
httpx -u "$domain" | tee -a "$output_file"
