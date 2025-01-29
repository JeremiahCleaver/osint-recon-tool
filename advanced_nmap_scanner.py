import subprocess
import json
import argparse
import smtplib
import whois
from email.mime.text import MIMEText

# SMTP Configuration (Optional)
SMTP_SERVER = "smtp.example.com"  # Replace with actual SMTP server
SMTP_PORT = 587
EMAIL_USER = "your_email@example.com"
EMAIL_PASS = "your_password"
EMAIL_TO = "alert@example.com"

# Function to run Nmap
def run_nmap_scan(target, scan_type):
    scan_modes = {
        "quick": "-F",
        "full": "-p-",
        "aggressive": "-A",
        "stealth": "-sS"
    }

    if scan_type not in scan_modes:
        print("Invalid scan type! Choose from: quick, full, aggressive, stealth")
        return None

    command = ["nmap", scan_modes[scan_type], "-oX", "-", target]
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout

# Parse Nmap XML Output into JSON
def parse_nmap_output(xml_output):
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml_output)
    scan_data = {"hosts": []}

    for host in root.findall("host"):
        ip_addr = host.find("address").attrib["addr"]
        open_ports = []

        for port in host.findall(".//port"):
            port_id = port.attrib["portid"]
            service = port.find("service").attrib.get("name", "unknown")
            state = port.find("state").attrib["state"]

            if state == "open":
                open_ports.append({"port": port_id, "service": service})

        scan_data["hosts"].append({"ip": ip_addr, "open_ports": open_ports})

    return scan_data

# WHOIS Lookup Function
def get_whois_info(target):
    try:
        whois_info = whois.whois(target)
        return {
            "domain_name": whois_info.domain_name,
            "registrar": whois_info.registrar,
            "creation_date": whois_info.creation_date,
            "expiration_date": whois_info.expiration_date
        }
    except Exception as e:
        return {"error": str(e)}

# Save results to JSON
def save_results_to_json(results, filename="nmap_results.json"):
    with open(filename, "w") as json_file:
        json.dump(results, json_file, indent=4)

# Email Notification
def send_email_notification(scan_results):
    try:
        msg_body = json.dumps(scan_results, indent=4)
        msg = MIMEText(msg_body)
        msg["Subject"] = "Nmap Scan Alert: Open Ports Detected"
        msg["From"] = EMAIL_USER
        msg["To"] = EMAIL_TO

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_USER, EMAIL_TO, msg.as_string())

        print("Email notification sent!")
    except Exception as e:
        print(f"Email error: {e}")

# Main function
def main():
    parser = argparse.ArgumentParser(description="Advanced Automated Nmap Scanner")
    parser.add_argument("target", type=str, help="Target IP or domain (or file containing multiple targets)")
    parser.add_argument("scan_type", choices=["quick", "full", "aggressive", "stealth"], help="Type of Nmap scan")

    args = parser.parse_args()
    targets = []

    # Check if input is a file with multiple targets
    try:
        with open(args.target, "r") as f:
            targets = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        targets.append(args.target)

    all_results = {"scans": []}

    for target in targets:
        print(f"Scanning: {target} with {args.scan_type} mode")
        scan_result = run_nmap_scan(target, args.scan_type)

        if scan_result:
            parsed_results = parse_nmap_output(scan_result)
            whois_data = get_whois_info(target)
            parsed_results["whois"] = whois_data
            all_results["scans"].append(parsed_results)

    save_results_to_json(all_results)
    print("Results saved to nmap_results.json")

    # Send email notification if open ports are found
    if any(host["open_ports"] for host in all_results["scans"]):
        send_email_notification(all_results)

if __name__ == "__main__":
    main()
