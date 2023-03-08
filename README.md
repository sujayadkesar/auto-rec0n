<img width="646" alt="image" src="https://user-images.githubusercontent.com/95465072/191881886-b688a3a4-9649-45e2-a0d3-4bf0e55a912a.png">


# Auto Recon

Auto Recon is a Bash script for automating the reconnaissance phase of penetration testing. It performs various types of scans to gather information about the target domain, including IP details, domain reconnaissance, vulnerability scanning, network mapping, application fingerprinting, and Google dorks.

## Disclaimer

This script uses all the active scan methods, which may trigger the backend monitoring systems. Use this tool at your own risk!

## Prerequisites

To run this script, you need to have the following tools installed:

-   `toilet`
-   `figlet`
-   `wig`
-   `nmap`
-   `jq`

## Usage

To use this script, simply run the `auto-recon.sh` file and enter the target domain name when prompted. The script will create a directory called `results-{domain-name}` in the current working directory and save the scan results in various subdirectories within it.

## Output

The `results-{domain-name}` directory contains the following subdirectories:

-   `Domain-reconnaissance`: Contains information about the target domain, including IP addresses, subdomains, and SSL certificate details.
-   `Vulnerability-scanning`: Contains vulnerability scan reports generated using various tools, such as `nmap` and `nikto`.
-   `Network-mapping`: Contains network maps generated using tools like `nmap`.
-   `Application-fingerprinting`: Contains information about the web technologies used by the target website, obtained using `wig`.
-   `Google-dorks`: Contains Google dorks specific to the target domain.
-   `Screenshots`: Contains screenshots of the target website, generated using tools like `aquatone`.
-   `Reporting`: Contains various reports generated during the reconnaissance phase.

## Contributin

## Installation


``` 
 git clone https://github.com/sujayadkesar/auto-rec0n.git
 ```
``` 
cd auto-rec0n
```
``` 
chmod +x auto-rec0n.sh 
```
``` 
./auto-rec0n.sh 
```
> **Note** : To access this tool from any directory  
> ```
>  ln -sf <complete path to auto-rec0n.sh> /usr/local/bin/auto-recon
>  ```

``` bash
``` 

## Reconnaissance

 <img width="749" alt="image" src="https://user-images.githubusercontent.com/95465072/191880370-3183e421-59a9-49f8-8109-6f7eed865caa.png">


 - [ ] nslookup
 - [ ] host_discovery
 - [ ] dig utilities
 - [ ] dnsrecon
 - [ ] whatweb
 - [ ] wafw00f
 - [ ] nmap
 - [ ] nmap-script-engines
 - [ ] theHarvester
 - [ ] adding much more soon!!

## 🤝 **Contributing**

Contributions to Auto-recon are welcome and encouraged! If you would like to contribute, please follow these steps:

1.  Fork the Auto-recon repository
2.  Create a new branch for your feature or bug fix
3.  Make your changes and test them thoroughly
4.  Submit a pull request to the main Auto-recon repository

> Before submitting a pull request, please make sure to run the tests and update the documentation as necessary.


> **Warning!!** : This auto recon uses all the active scan methods it may trigger the backend monitoring systems. Use this tool with authorized access! 
