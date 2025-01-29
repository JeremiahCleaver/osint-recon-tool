# osint-recon-tool

### How to Use

1. Install dependencies:

```pip install python-whois```

2. Run the script for a single target:

```python advanced_nmap_scanner.py example.com quick```

3. Scan multiple targets from a file:
   
```python advanced_nmap_scanner.py targets.txt full```

The file targets.txt should contain one IP/domain per line.

4. Results are saved in nmap_results.json.

```Multiple scan types (quick, full, aggressive, stealth)
 WHOIS lookup for target domains
 Parses Nmap XML output into JSON
 Handles multiple targets from a file
 Sends email alerts for open ports
 JSON report generation for future analysis

