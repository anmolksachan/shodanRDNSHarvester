<!--# **`shodanRDNSHarvester` — Shodan RDNS Harvester**-->

<img width="1716" height="222" alt="image" src="https://github.com/user-attachments/assets/c764f7ff-84bc-4675-9ae2-5c4fea4386c1" />

### _Fast, threaded RDNS + Port/Vuln enumeration using internetdb.shodan.io (No API Key Needed)_

----------

## ⭐ Overview

`shodanRDNSHarvester` is a **multi-threaded RDNS + port + vulnerability enumerator** powered by:

-   **internetdb.shodan.io** (no API key needed)
    
-   Local **socket.gethostbyaddr()** reverse DNS fallback
    
-   Full support for:
    
    -   Single IP (`--ip`)
        
    -   Single domain (`--domain`)
        
    -   File input with mixed IPs/domains (`--file`)
        

The tool automatically:

-   Creates a project folder based on the input you provide
    
-   Generates **TXT**, **CSV** (optional), and **master JSON** reports
    
-   Creates per-target folders with timestamped results
    
-   Produces clean table output + optional verbose mode
    

Perfect for **OSINT, recon, red teaming, threat intel, and attack surface mapping**.

----------

## 🚀 Features

-   🔍 **RDNS resolution** via Shodan’s InternetDB
    
-   🚫 **No API key required**
    
-   🚀 **Fast multi-threaded** enumeration
    
-   🧠 **Automatic project folder naming**
    
-   📁 Per-target folders:
    
    -   `.txt` human-readable reports
        
    -   Optional `.csv`
        
-   📦 A **master JSON/CSV** aggregator
    
-   🎨 Beautiful ASCII banner
    
-   🛡 Safe filename sanitization
    
-   🪝 Clean tabular CLI output
    

----------

## 📦 Installation

### **Clone the repository**

```bash
git clone https://github.com/anmolksachan/shodanRDNSHarvester.git
```
```bash
cd shodanRDNSHarvester
```

### **Install dependencies**

```bash
pip3 install -r requirements.txt
```

----------

## 📌 Usage

### **1. Scan a single IP**

```bash
python3 shodanRDNSHarvester.py --ip 8.8.8.8
```

### **2. Scan a single domain**

```bash
python3 shodanRDNSHarvester.py --domain example.com
```

### **3. Scan from a file (mixed IPs and domains)**

```bash
python3 shodanRDNSHarvester.py --file targets.txt
```

### **4. Enable verbose mode**

```bash
python3 shodanRDNSHarvester.py --ip 44.228.249.3 --verbose
```

### **5. Generate CSV outputs as well**

```bash
python3 shodanRDNSHarvester.py --file scope.txt --csv
```

### **6. Increase thread count**

```bash
python3 shodanRDNSHarvester.py --file scope.txt --threads 50
```

----------

## 📁 Output Structure

Example run:

```
python3 shodanRDNSHarvester.py --ip 44.228.249.3 --csv
```

Creates:

```
LastScans/
└── 44.228.249.3_20251127-160536/
    ├── shodan-rdns_master_20251127-160536.json
    ├── shodan-rdns_master_20251127-160536.csv
    ├── 44.228.249.3_20251127-160536/
    │   ├── 44.228.249.3_20251127-160536.txt
    │   └── 44.228.249.3_20251127-160536.csv

```

----------

## 🧪 CLI Output Example

```
[+] domains resolved/provided: 0
[+] unique ips to query: 1

IP                HOSTNAME (primary)                        PORTS  VULNS  FROM_DOMAIN
-----------------------------------------------------------------------------------------
44.228.249.3      ec2-44-228-249-3.us-west-2.compute.amazonaws.com      1     22  -

```

----------

## 📝 Generated TXT Example

```
Target: 44.228.249.3
Timestamp (UTC): 2025-11-27T16:05:36+00:00

Hostnames (PTRs / internetdb / socket):
 - ec2-44-228-249-3.us-west-2.compute.amazonaws.com

Ports:
22

Vulns:
- None

Source domains:
 - None

```

----------

## ⚙️ Command-line Options

Flag

Description

`--domain example.com`

Scan a single domain

`--ip 1.2.3.4`

Scan a single IP

`--file targets.txt`

Scan a file with IPs/domains

`--threads 20`

Set custom thread count

`--verbose`

Show detailed hosts, ports, vulns

`--csv`

Save per-target + master CSV

----------

## 🧼 Safe File & Folder Names

Project folder name is auto-derived from input:

-   `--ip 1.2.3.4` → `LastScans/1.2.3.4_<timestamp>`
    
-   `--domain example.com` → `LastScans/example.com_<timestamp>`
    
-   `--file scope.txt` → `LastScans/scope.txt_<timestamp>`
    

All filenames are sanitized to avoid OS path issues.

----------

## ❤️ Credits

Made with ☕ + ⚡ by **FR13ND0x7F**

InternetDB by **Shodan**  
ASCII art included as provided 🎨

----------

## 📄 License

[GPL-3.0-1](https://github.com/anmolksachan/shodanRDNSHarvester?tab=GPL-3.0-1-ov-file#readme)

----------

