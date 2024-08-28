#!/bin/bash

# List of required tools
tools=(
  "whois"
  "reverseip"
  "nmap"
  "masscan"
  "nikto"
  "wpscan"
  "testssl"
  "sqlmap"
  "xsstrike"
  "curl"
  "wappalyzer"
  "whatweb"
  "dirb"
  "gobuster"
  "ffuf"
  "wfuzz"
  "sublist3r"
  "assetfinder"
  "amass"
  "subfinder"
  "crt.sh"
  "theharvester"
  "arp-scan"
  "passive-dns"
  "dnsenum"
  "ffuf"
  "wpscan"
  "testssl"
  "curl"
  "jq"
)

# Check if each tool is installed
for tool in "${tools[@]}"; do
  if command -v "$tool" &> /dev/null; then
    echo "$tool is installed."
  else
    echo "$tool is not installed. Please install it to proceed."
    missing_tools=true
  fi
done

if [ "$missing_tools" = true ]; then
  echo "Some tools are missing. Please install them before running the script."
  exit 1
fi

echo "All required tools are installed."


# Define the domain and output file
domain="$1"
timestamp=$(date +"%Y%m%d_%H%M%S")
output_file="${domain}_${timestamp}.txt"

# Function to log output with timestamp
log_output() {
    echo "[$(date)] $1" | tee -a "$output_file"
}

# Check if required tools are installed
check_tools() {
    for tool in whois dig nmap curl whatweb dirb gobuster ffuf nikto sqlmap xsstrike sublist3r assetfinder amass wappalyzer sslyze; do
        if ! command -v "$tool" &> /dev/null; then
            echo "$tool could not be found. Please install it." | tee -a "$output_file"
            exit 1
        fi
    done
}

# Run the tool check
check_tools

# Start timing
start_time=$(date +%s)

# Initial Domain Information Gathering
log_output "1. WHOIS Lookup"
whois "$domain" | tee -a "$output_file"

log_output "2. DNS Zone Transfer"
dig axfr "$domain" | tee -a "$output_file"

log_output "3. DNS Records Enumeration"
dig any "$domain" | tee -a "$output_file"

log_output "4. Reverse DNS Lookup"
for ip in $(dig +short "$domain"); do
    dig -x "$ip" | tee -a "$output_file"
done

# Port Scanning
log_output "5. Full Port Scan with nmap"
nmap -p- "$domain" -oN "$output_file" -v

log_output "6. Service Version Detection with nmap"
nmap -sV "$domain" -oN "$output_file" -v

log_output "7. OS Detection with nmap"
nmap -O "$domain" -oN "$output_file" -v

log_output "8. Top 1000 Ports Scan with nmap"
nmap --top-ports 1000 "$domain" -oN "$output_file"

log_output "9. Aggressive Scan with nmap"
nmap -A "$domain" -oN "$output_file"

log_output "10. TCP Connect Scan with nmap"
nmap -sT "$domain" -oN "$output_file"

log_output "11. UDP Scan with nmap"
nmap -sU "$domain" -oN "$output_file"

log_output "12. Scan with nmap Scripting Engine"
nmap --script=default "$domain" -oN "$output_file"

log_output "13. OS Fingerprinting with nmap"
nmap -O -p- "$domain" -oN "$output_file"

log_output "14. Scan for specific port ranges with nmap"
nmap -p 22,80,443 "$domain" -oN "$output_file"

# Web Application Enumeration
log_output "15. HTTP Headers with curl"
curl -I "$domain" | tee -a "$output_file"

log_output "16. Web Server Fingerprinting with WhatWeb"
whatweb "$domain" | tee -a "$output_file"

log_output "17. Directory Brute Forcing with dirb"
dirb "http://$domain" /usr/share/wordlists/dirb/common.txt | tee -a "$output_file"

log_output "18. Directory Brute Forcing with gobuster"
gobuster dir -u "http://$domain" -w /usr/share/wordlists/dirb/common.txt | tee -a "$output_file"

log_output "19. File and Directory Brute Forcing with ffuf"
ffuf -u "http://$domain/FUZZ" -w /usr/share/wordlists/dirb/common.txt -o "$output_file" | tee -a "$output_file"

log_output "20. Directory Brute Forcing with dirb (big)"
dirb "http://$domain" /usr/share/wordlists/dirb/big.txt | tee -a "$output_file"

log_output "21. Directory Brute Forcing with gobuster (big)"
gobuster dir -u "http://$domain" -w /usr/share/wordlists/dirb/big.txt | tee -a "$output_file"

log_output "22. Directory and File Enumeration with wfuzz"
wfuzz -c -w /usr/share/wordlists/dirb/common.txt -u "http://$domain/FUZZ" | tee -a "$output_file"

log_output "23. HTTP Methods with curl"
curl -X OPTIONS "$domain" -i | tee -a "$output_file"

log_output "24. Web Application Fingerprinting with wappalyzer"
wappalyzer "$domain" | tee -a "$output_file"

log_output "25. Web Scanning with Nikto"
nikto -h "$domain" | tee -a "$output_file"

log_output "26. SQL Injection Testing with sqlmap"
sqlmap -u "http://$domain/vulnerable.php?id=1" --batch --dump | tee -a "$output_file"

log_output "27. XSS Testing with xsstrike"
xsstrike -u "http://$domain/vulnerable.php?id=1" | tee -a "$output_file"

# Subdomain Enumeration
log_output "28. Subdomain Enumeration with sublist3r"
sublist3r -d "$domain" -o "$output_file"

log_output "29. Subdomain Enumeration with assetfinder"
assetfinder --subs-only "$domain" | tee -a "$output_file"

log_output "30. Subdomain Enumeration with amass"
amass enum -d "$domain" | tee -a "$output_file"

log_output "31. Subdomain Enumeration with subfinder"
subfinder -d "$domain" -o "$output_file"

log_output "32. Subdomain Enumeration with crt.sh"
curl "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[] | .name_value' | tee -a "$output_file"

log_output "33. Subdomain Enumeration with theHarvester"
theharvester -d "$domain" -b google | tee -a "$output_file"

# Network Scanning
log_output "34. Network Scanning with nmap"
nmap -sP "$domain" -oN "$output_file" -v

log_output "35. Local Network Scan with arp-scan"
arp-scan --localnet | tee -a "$output_file"

log_output "36. Open Ports and Services with masscan"
masscan "$domain" -p1-65535 | tee -a "$output_file"

log_output "37. Passive DNS Reconnaissance with passive-dns"
passive-dns -d "$domain" | tee -a "$output_file"

# Additional Web Enumeration
log_output "38. SSL/TLS Configuration with sslyze"
sslyze --regular "$domain" | tee -a "$output_file"

log_output "39. Cross-Site Scripting (XSS) with xsstrike"
xsstrike -u "http://$domain/vulnerable.php?id=1" | tee -a "$output_file"

log_output "40. Open Redirect Testing"
curl -I "http://$domain/redirect?url=http://evil.com" | tee -a "$output_file"

# Additional Active Reconnaissance
log_output "41. HTTP Security Headers with whatweb"
whatweb "$domain" | tee -a "$output_file"

log_output "42. Cross-Site Request Forgery (CSRF) Testing"
curl -I "$domain/vulnerable.php?csrf_token=123456" | tee -a "$output_file"

log_output "43. Session Management Testing"
curl -I "$domain/login" -b "session=123456" | tee -a "$output_file"

log_output "44. Information Disclosure Testing"
curl -I "$domain/sensitive_info" | tee -a "$output_file"

log_output "45. Directory Listing"
curl -I "$domain" | grep "Directory listing" | tee -a "$output_file"

# Brute Forcing and Fuzzing
log_output "46. HTTP Fuzzing with wfuzz"
wfuzz -c -w /usr/share/wordlists/dirb/common.txt -u "http://$domain/FUZZ" | tee -a "$output_file"

log_output "47. DNS Brute Forcing with dnsenum"
dnsenum "$domain" | tee -a "$output_file"

log_output "48. Directory Brute Forcing with dirb"
dirb "http://$domain" /usr/share/wordlists/dirb/common.txt | tee -a "$output_file"

log_output "49. Directory Brute Forcing with gobuster"
gobuster dir -u "http://$domain" -w /usr/share/wordlists/dirb/common.txt | tee -a "$output_file"

log_output "50. URL Fuzzing with ffuf"
ffuf -u "http://$domain/FUZZ" -w /usr/share/wordlists/dirb/common.txt | tee -a "$output_file"

# Additional Directory and File Scanning
log_output "51. Directory Brute Forcing with dirb (big)"
dirb "http://$domain" /usr/share/wordlists/dirb/big.txt | tee -a "$output_file"

log_output "52. Directory Brute Forcing with gobuster (big)"
gobuster dir -u "http://$domain" -w /usr/share/wordlists/dirb/big.txt | tee -a "$output_file"

log_output "53. Directory and File Enumeration with wfuzz"
wfuzz -c -w /usr/share/wordlists/dirb/big.txt -u "http://$domain/FUZZ" | tee -a "$output_file"

# More In-depth Scanning
log_output "54. Port Scanning with masscan"
masscan "$domain" -p1-65535 | tee -a "$output_file"

log_output "55. Full Port Scan with nmap (verbose)"
nmap -p- -v "$domain" | tee -a "$output_file"

log_output "56. Detailed Web Scan with nikto"
nikto -h "$domain" -display V | tee -a "$output_file"

log_output "57. Web Scanning with wpscan"
wpscan --url "$domain" --enumerate vp | tee -a "$output_file"

log_output "58. SSL/TLS Testing with testssl"
testssl --full "$domain" | tee -a "$output_file"

log_output "59. HTTP Methods Testing with curl"
curl -X OPTIONS "$domain" -i | tee -a "$output_file"

# Advanced Vulnerability Testing
log_output "60. SQL Injection Testing with sqlmap"
sqlmap -u "http://$domain/vulnerable.php?id=1" --batch --level=5 --risk=3 | tee -a "$output_file"

log_output "61. XSS Testing with xsstrike"
xsstrike -u "http://$domain/vulnerable.php?id=1" --level=3 | tee -a "$output_file"

log_output "62. Open Redirect Testing"
curl -I "$domain/redirect?url=http://evil.com" | tee -a "$output_file"

log_output "63. Cross-Site Request Forgery (CSRF) Testing"
curl -I "$domain/vulnerable.php?csrf_token=123456" | tee -a "$output_file"

log_output "64. Session Management Testing"
curl -I "$domain/login" -b "session=123456" | tee -a "$output_file"

log_output "65. Information Disclosure Testing"
curl -I "$domain/sensitive_info" | tee -a "$output_file"

log_output "66. Directory Listing"
curl -I "$domain" | grep "Directory listing" | tee -a "$output_file"

# Web Enumeration with Various Tools
log_output "67. Web Fingerprinting with wappalyzer"
wappalyzer "$domain" | tee -a "$output_file"

log_output "68. Web Application Scanning with whatweb"
whatweb "$domain" | tee -a "$output_file"

log_output "69. Directory Scanning with dirb"
dirb "http://$domain" /usr/share/wordlists/dirb/common.txt | tee -a "$output_file"

log_output "70. Directory Scanning with gobuster"
gobuster dir -u "http://$domain" -w /usr/share/wordlists/dirb/common.txt | tee -a "$output_file"

# Enumeration and Scanning
log_output "71. Subdomain Enumeration with sublist3r"
sublist3r -d "$domain" -o "$output_file"

log_output "72. Subdomain Enumeration with assetfinder"
assetfinder --subs-only "$domain" | tee -a "$output_file"

log_output "73. Subdomain Enumeration with amass"
amass enum -d "$domain" | tee -a "$output_file"

log_output "74. Subdomain Enumeration with subfinder"
subfinder -d "$domain" -o "$output_file"

log_output "75. Subdomain Enumeration with crt.sh"
curl "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[] | .name_value' | tee -a "$output_file"

log_output "76. Subdomain Enumeration with theHarvester"
theharvester -d "$domain" -b google | tee -a "$output_file"

# Network Scanning
log_output "77. Network Scanning with nmap"
nmap -sP "$domain" -oN "$output_file" -v

log_output "78. Local Network Scan with arp-scan"
arp-scan --localnet | tee -a "$output_file"

log_output "79. Open Ports and Services with masscan"
masscan "$domain" -p1-65535 | tee -a "$output_file"

log_output "80. Passive DNS Reconnaissance with passive-dns"
passive-dns -d "$domain" | tee -a "$output_file"

# Scanning and Fuzzing
log_output "81. URL Fuzzing with ffuf"
ffuf -u "http://$domain/FUZZ" -w /usr/share/wordlists/dirb/common.txt | tee -a "$output_file"

log_output "82. Directory Brute Forcing with dirb (big)"
dirb "http://$domain" /usr/share/wordlists/dirb/big.txt | tee -a "$output_file"

log_output "83. Directory Brute Forcing with gobuster (big)"
gobuster dir -u "http://$domain" -w /usr/share/wordlists/dirb/big.txt | tee -a "$output_file"

log_output "84. Directory and File Enumeration with wfuzz"
wfuzz -c -w /usr/share/wordlists/dirb/big.txt -u "http://$domain/FUZZ" | tee -a "$output_file"

# More Advanced Scanning
log_output "85. Detailed Web Scan with nikto"
nikto -h "$domain" -display V | tee -a "$output_file"

log_output "86. Web Scanning with wpscan"
wpscan --url "$domain" --enumerate vp | tee -a "$output_file"

log_output "87. SSL/TLS Testing with testssl"
testssl --full "$domain" | tee -a "$output_file"

log_output "88. DNS Brute Forcing with dnsenum"
dnsenum "$domain" | tee -a "$output_file"

log_output "89. HTTP Methods Testing with curl"
curl -X OPTIONS "$domain" -i | tee -a "$output_file"

# Additional Network Scanning and Fuzzing
log_output "90. Network Scanning with nmap"
nmap -sP "$domain" -oN "$output_file" -v

log_output "91. Local Network Scan with arp-scan"
arp-scan --localnet | tee -a "$output_file"

log_output "92. Open Ports and Services with masscan"
masscan "$domain" -p1-65535 | tee -a "$output_file"

log_output "93. Passive DNS Reconnaissance with passive-dns"
passive-dns -d "$domain" | tee -a "$output_file"

# Advanced Directory and File Scanning
log_output "94. Directory Scanning with dirb"
dirb "http://$domain" /usr/share/wordlists/dirb/common.txt | tee -a "$output_file"

log_output "95. Directory Scanning with gobuster"
gobuster dir -u "http://$domain" -w /usr/share/wordlists/dirb/common.txt | tee -a "$output_file"

log_output "96. Directory Brute Forcing with ffuf"
ffuf -u "http://$domain/FUZZ" -w /usr/share/wordlists/dirb/common.txt | tee -a "$output_file"

# Brute Forcing and Enumeration
log_output "97. Directory and File Brute Forcing with dirb"
dirb "http://$domain" /usr/share/wordlists/dirb/big.txt | tee -a "$output_file"

log_output "98. Directory and File Brute Forcing with gobuster"
gobuster dir -u "http://$domain" -w /usr/share/wordlists/dirb/big.txt | tee -a "$output_file"

log_output "99. File and Directory Enumeration with wfuzz"
wfuzz -c -w /usr/share/wordlists/dirb/big.txt -u "http://$domain/FUZZ" | tee -a "$output_file"

# Comprehensive Scanning
log_output "100. Full Port Scan with nmap (verbose)"
nmap -p- -v "$domain" | tee -a "$output_file"

log_output "101. Aggressive Scan with nmap"
nmap -A "$domain" -oN "$output_file" | tee -a "$output_file"

log_output "102. Detailed Web Scanning with nikto"
nikto -h "$domain" -display V | tee -a "$output_file"

log_output "103. Comprehensive Web Scanning with wpscan"
wpscan --url "$domain" --enumerate vp | tee -a "$output_file"

log_output "104. SSL/TLS Testing with testssl"
testssl --full "$domain" | tee -a "$output_file"

log_output "105. Detailed DNS Enumeration with dnsenum"
dnsenum "$domain" | tee -a "$output_file"

# Additional Web and Network Scanning
log_output "106. Network Scanning with nmap"
nmap -sP "$domain" -oN "$output_file" -v

log_output "107. Local Network Scan with arp-scan"
arp-scan --localnet | tee -a "$output_file"

log_output "108. Open Ports and Services with masscan"
masscan "$domain" -p1-65535 | tee -a "$output_file"

log_output "109. Passive DNS Reconnaissance with passive-dns"
passive-dns -d "$domain" | tee -a "$output_file"

log_output "110. Cross-Site Request Forgery (CSRF) Testing"
curl -I "$domain/vulnerable.php?csrf_token=123456" | tee -a "$output_file"

log_output "111. Session Management Testing"
curl -I "$domain/login" -b "session=123456" | tee -a "$output_file"

log_output "112. Information Disclosure Testing"
curl -I "$domain/sensitive_info" | tee -a "$output_file"

log_output "113. Directory Listing"
curl -I "$domain" | grep "Directory listing" | tee -a "$output_file"

# Comprehensive Web Scanning and Fuzzing
log_output "114. Web Application Scanning with nikto"
nikto -h "$domain" | tee -a "$output_file"

log_output "115. Web Application Scanning with wpscan"
wpscan --url "$domain" --enumerate vp | tee -a "$output_file"

log_output "116. SSL/TLS Testing with testssl"
testssl --full "$domain" | tee -a "$output_file"

log_output "117. DNS Brute Forcing with dnsenum"
dnsenum "$domain" | tee -a "$output_file"

log_output "118. HTTP Methods Testing with curl"
curl -X OPTIONS "$domain" -i | tee -a "$output_file"

# Further Enumeration and Fuzzing
log_output "119. Directory Scanning with dirb"
dirb "http://$domain" /usr/share/wordlists/dirb/common.txt | tee -a "$output_file"

log_output "120. Directory Scanning with gobuster"
gobuster dir -u "http://$domain" -w /usr/share/wordlists/dirb/common.txt | tee -a "$output_file"

log_output "121. Directory Brute Forcing with ffuf"
ffuf -u "http://$domain/FUZZ" -w /usr/share/wordlists/dirb/common.txt | tee -a "$output_file"

log_output "122. Directory Brute Forcing with dirb (big)"
dirb "http://$domain" /usr/share/wordlists/dirb/big.txt | tee -a "$output_file"

log_output "123. Directory Brute Forcing with gobuster (big)"
gobuster dir -u "http://$domain" -w /usr/share/wordlists/dirb/big.txt | tee -a "$output_file"

log_output "124. Directory and File Enumeration with wfuzz"
wfuzz -c -w /usr/share/wordlists/dirb/big.txt -u "http://$domain/FUZZ" | tee -a "$output_file"

# Advanced Network Scanning
log_output "125. Full Port Scan with nmap (verbose)"
nmap -p- -v "$domain" | tee -a "$output_file"

log_output "126. Aggressive Scan with nmap"
nmap -A "$domain" -oN "$output_file" | tee -a "$output_file"

log_output "127. Detailed Web Scanning with nikto"
nikto -h "$domain" -display V | tee -a "$output_file"

log_output "128. Comprehensive Web Scanning with wpscan"
wpscan --url "$domain" --enumerate vp | tee -a "$output_file"

log_output "129. SSL/TLS Testing with testssl"
testssl --full "$domain" | tee -a "$output_file"

log_output "130. Detailed DNS Enumeration with dnsenum"
dnsenum "$domain" | tee -a "$output_file"

log_output "131. Cross-Site Request Forgery (CSRF) Testing"
curl -I "$domain/vulnerable.php?csrf_token=123456" | tee -a "$output_file"

log_output "132. Session Management Testing"
curl -I "$domain/login" -b "session=123456" | tee -a "$output_file"

log_output "133. Information Disclosure Testing"
curl -I "$domain/sensitive_info" | tee -a "$output_file"

log_output "134. Directory Listing"
curl -I "$domain" | grep "Directory listing" | tee -a "$output_file"

# Additional Network and Web Scanning
log_output "135. Network Scanning with nmap"
nmap -sP "$domain" -oN "$output_file" -v

log_output "136. Local Network Scan with arp-scan"
arp-scan --localnet | tee -a "$output_file"

log_output "137. Open Ports and Services with masscan"
masscan "$domain" -p1-65535 | tee -a "$output_file"

log_output "138. Passive DNS Reconnaissance with passive-dns"
passive-dns -d "$domain" | tee -a "$output_file"

log_output "139. Cross-Site Request Forgery (CSRF) Testing"
curl -I "$domain/vulnerable.php?csrf_token=123456" | tee -a "$output_file"

log_output "140. Session Management Testing"
curl -I "$domain/login" -b "session=123456" | tee -a "$output_file"

log_output "141. Information Disclosure Testing"
curl -I "$domain/sensitive_info" | tee -a "$output_file"

log_output "142. Directory Listing"
curl -I "$domain" | grep "Directory listing" | tee -a "$output_file"

# More Enumeration and Scanning
log_output "143. Directory Scanning with dirb"
dirb "http://$domain" /usr/share/wordlists/dirb/common.txt | tee -a "$output_file"

log_output "144. Directory Scanning with gobuster"
gobuster dir -u "http://$domain" -w /usr/share/wordlists/dirb/common.txt | tee -a "$output_file"

log_output "145. Directory Brute Forcing with ffuf"
ffuf -u "http://$domain/FUZZ" -w /usr/share/wordlists/dirb/common.txt | tee -a "$output_file"

log_output "146. Directory Brute Forcing with dirb (big)"
dirb "http://$domain" /usr/share/wordlists/dirb/big.txt | tee -a "$output_file"

log_output "147. Directory Brute Forcing with gobuster (big)"
gobuster dir -u "http://$domain" -w /usr/share/wordlists/dirb/big.txt | tee -a "$output_file"

log_output "148. Directory and File Enumeration with wfuzz"
wfuzz -c -w /usr/share/wordlists/dirb/big.txt -u "http://$domain/FUZZ" | tee -a "$output_file"

# Comprehensive Reconnaissance
log_output "149. Full Port Scan with nmap (verbose)"
nmap -p- -v "$domain" | tee -a "$output_file"

log_output "150. Aggressive Scan with nmap"
nmap -A "$domain" -oN "$output_file" | tee -a "$output_file"

log_output "151. Detailed Web Scanning with nikto"
nikto -h "$domain" -display V | tee -a "$output_file"

log_output "152. Comprehensive Web Scanning with wpscan"
wpscan --url "$domain" --enumerate vp | tee -a "$output_file"

log_output "153. SSL/TLS Testing with testssl"
testssl --full "$domain" | tee -a "$output_file"

log_output "154. Detailed DNS Enumeration with dnsenum"
dnsenum "$domain" | tee -a "$output_file"

log_output "155. Cross-Site Request Forgery (CSRF) Testing"
curl -I "$domain/vulnerable.php?csrf_token=123456" | tee -a "$output_file"

log_output "156. Session Management Testing"
curl -I "$domain/login" -b "session=123456" | tee -a "$output_file"

log_output "157. Information Disclosure Testing"
curl -I "$domain/sensitive_info" | tee -a "$output_file"

log_output "158. Directory Listing"
curl -I "$domain" | grep "Directory listing" | tee -a "$output_file"

# Final steps
end_time=$(date +%s)
execution_time=$((end_time - start_time))

log_output "Reconnaissance completed in $execution_time seconds. Results saved to $output_file."
