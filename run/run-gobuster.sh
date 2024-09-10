#!/bin/bash

# Check if the correct number of arguments is provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <target_url> <wordlist_path> <output_file>"
    exit 1
fi

# Assign command-line arguments to variables
TARGET_URL="$1"
WORDLIST="$2"
OUTPUT_FILE="$3"

# Basic directory brute-forcing with extensions
echo "[*] Running basic directory brute-forcing with extensions..."
ffuf -u "$TARGET_URL/FUZZ" -w "$WORDLIST" -e .php,.html,.js -o "$OUTPUT_FILE" -of json
echo "[*] Basic directory brute-forcing completed. Results saved to $OUTPUT_FILE."

# Advanced scan with status code filtering and rate limiting
echo "[*] Running advanced scan with status code filtering and rate limiting..."
ffuf -u "$TARGET_URL/FUZZ" -w "$WORDLIST" -mc 200,204,301,302 -fc 403,404 -rate 10 -p 0.5 -o "filtered_results.json" -of json
echo "[*] Advanced scan completed. Results saved to filtered_results.json."

# Recursive scan with custom headers
echo "[*] Running recursive scan with custom headers..."
ffuf -u "$TARGET_URL/FUZZ" -w "$WORDLIST" -recursion -recursion-depth 2 -r -H "User-Agent: CustomUserAgent" -H "Accept-Encoding: gzip, deflate" -o "recursive_results.json" -of json
echo "[*] Recursive scan completed. Results saved to recursive_results.json."

# Directory brute-forcing with proxy usage
echo "[*] Running scan with proxy..."
ffuf -u "$TARGET_URL/FUZZ" -w "$WORDLIST" -x http://127.0.0.1:8080 -o "proxy_results.json" -of json
echo "[*] Scan with proxy completed. Results saved to proxy_results.json."

# Scan with client certificate authentication
echo "[*] Running scan with client certificate authentication..."
ffuf -u "$TARGET_URL/FUZZ" -w "$WORDLIST" -cc /path/to/client.crt -ck /path/to/client.key -o "client_cert_results.json" -of json
echo "[*] Scan with client certificate authentication completed. Results saved to client_cert_results.json."

# Basic scan with rate limiting and delay between requests
echo "[*] Running basic scan with rate limiting and delay..."
ffuf -u "$TARGET_URL/FUZZ" -w "$WORDLIST" -rate 5 -p 1.0 -o "rate_limited_results.json" -of json
echo "[*] Basic scan with rate limiting and delay completed. Results saved to rate_limited_results.json."

# Scan ignoring response body
echo "[*] Running scan ignoring response body..."
ffuf -u "$TARGET_URL/FUZZ" -w "$WORDLIST" -ignore-body -o "ignore_body_results.json" -of json
echo "[*] Scan ignoring response body completed. Results saved to ignore_body_results.json."

# Verbose scan with full URL and redirect location
echo "[*] Running verbose scan..."
ffuf -u "$TARGET_URL/FUZZ" -w "$WORDLIST" -v -o "verbose_results.json" -of json
echo "[*] Verbose scan completed. Results saved to verbose_results.json."

# Inform the user that all scans are complete
echo "[*] All scans completed. Check the results in the specified output files."
