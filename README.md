# VulnRetriever 

This tool is intended for scanning external IP addresses only.  VulnRetriever uses a combination of open source tools 
including Nmap, MITRE CVE, and NVD to gather information about the target IP address.

## How To Run A Scan

```
from vulnretriever import VulnRetriever

VulnRetriever.scan(address)

```

### External Scan Report Format

| Scan ID | Date | IP Address | IP Status | Protocol | Port | Port State | Service | CPE | Product | CVE |
| :-------| :--- | :--------- | :-------- | :------- | :--- | :--------- | :-------| :---| :-------| :---|

### Report Fields

- Scan ID:  Unique ID created for each line item for indexing
- Date:  Date the scan was started
- IP Address:  Public IP Address that was scanned
- IP Status:  Status of the IP as a result of a Ping attempt.  Up = Responded, Down = No Response
- Protocol:  Should always be TCP for this scan.  UDP scans are not performed
- Port:  Port ID or Port Number that was found
- Port State:  Port state from the scan
- Service:  Service found running.  Ex: SSH, FTP, HTTP...
- CPE:  Common Platform Enumeration (CPE) is a standardized method of describing and identifying classes of applications, operating systems, and hardware
- Product:  Name of the product running and if possible the version.  Ex.  OpenSSH 7.4
- CVE:  Vulnerability found.  If a product is found the CVE is based on the product.  If no product, the CVE is based on the CPE found.  If neither, CVE is blank


### What is coming next
- CVSS:  
- Whois:
- NS:
- MX:
- Netblocks:



