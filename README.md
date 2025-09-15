# CS331: Computer Networks - Assignment 1

This repository contains the solution for **Assignment 1**, which includes:  
- A custom **DNS Resolver** application  
- An **analysis of the Traceroute protocol**

---

## 📂 Project Components

### **Task 1: DNS Resolver**
- A Python-based client-server application.  
- The client parses a `.pcap` file, adds a custom header to DNS queries, and sends them to a custom server.  
- The server resolves the queries and logs the results.  

### **Task 2: Traceroute Analysis**
- A comparative study of the **traceroute utility** on Linux and Windows.  
- Findings are documented in the `Final_Report.pdf`.  
- Includes `analyzer.py`, which was used to inspect `.pcap` files captured during the Linux traceroute session.  

---

## ▶️ How to Run the DNS Resolver (Task 1)

### **Prerequisites**
- Python 3  
- [Scapy library](https://scapy.net/) → install using:  
  ```bash
  pip install scapy
## Instructions

1. Ensure the following files are in the same directory:
   - `client.py`
   - `server.py`
   - Required `.pcap` file (e.g., `6.pcap`)

2. Open **two terminals** in this directory.

3. **Start the server** in the first terminal:

```bash
python3 server.py
```

4. **Run the client** in the second terminal:

```bash
python3 client.py
```
After execution, the server will generate a `dns_resolver.log` file containing the results of the DNS queries.

---

## Traceroute Analysis (Task 2)

- The investigation and findings are documented in `Final_Report.pdf`.
- The repository also includes `analyzer.py`, which was used to inspect the `.pcap` file captured during the Linux traceroute session.
