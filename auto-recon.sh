#! /bin/bash


red='\e[31m'
green='\e[32m'
BLK='\e[30m'; blk='\e[90m'; BBLK='\e[40m'; bblk='\e[100m' #| Black   |
RED='\e[31m'; red='\e[91m'; BRED='\e[41m'; bred='\e[101m' #| Red     |
GRN='\e[32m'; grn='\e[92m'; BGRN='\e[42m'; bgrn='\e[102m' #| Green   |
YLW='\e[33m'; ylw='\e[93m'; BYLW='\e[43m'; bylw='\e[103m' #| Yellow  |
BLU='\e[34m'; blu='\e[94m'; BBLU='\e[44m'; bblu='\e[104m' #| Blue    |
MGN='\e[35m'; mgn='\e[95m'; BMGN='\e[45m'; bmgn='\e[105m' #| Magenta |
CYN='\e[36m'; cyn='\e[96m'; BCYN='\e[46m'; bcyn='\e[106m' #| Cyan    |
WHT='\e[37m'; wht='\e[97m'; BWHT='\e[47m'; bwht='\e[107m' #| White   |


echo -e "\n"
toilet -f mono9 -F border Auto Recon
echo -e "\n\n"


printf "$RED"
figlet -f term WARNING!!  This auto recon uses all the active scan methods it may trigger the backend monitoring systems \n Use this tool at your own risk!!



# Define the target domain
echo -e "${CYN}\nEnter the target Domain name\n"
read target




# Create the results directory
results_dir=results-$target
mkdir $results_dir

# Create subdirectories for each category of information
mkdir $results_dir/Domain-reconnaissance
mkdir $results_dir/Vulnerability-scanning
mkdir $results_dir/Network-mapping
mkdir $results_dir/Application-fingerprinting
mkdir $results_dir/Google-dorks
mkdir $results_dir/Screenshots
mkdir $results_dir/Reporting



# ----------LONG PROCESSES---------------------
yes | wig $target >> $results_dir/Application-fingerprinting/technologies.txt &
#______________________________________________



website_name=$target
printf "$YLW"
echo -e "\n\n*================{   IP Details   }================*\n\n" > $results_dir/Domain-reconnaissance/ip_addresses.txt

echo -e "\n\033[0;35m\033[1m\tHost name: \033[1m\033[0;32m \t${website_name} \n" >> $results_dir/Domain-reconnaissance/ip_addresses.txt


host_ip=$(host $website_name | awk '/has address/ { print $4 }')


echo -e "\n\033[0;35m\033[1m\tDomain IP: \033[1m\033[0;32m \t${host_ip} \n" >> $results_dir/Domain-reconnaissance/ip_addresses.txt
echo -e "\n\n\033[0;35m\033[1m\tDouble IP verification using IPinfo.io" >> $results_dir/Domain-reconnaissance/ip_addresses.txt
echo -e "\n\033[0;35m\033[1m\tResults:\033[0m\033[0;32m" >> $results_dir/Domain-reconnaissance/ip_addresses.txt


response=$(curl -s https://ipinfo.io/$host_ip/json)


ip=$(echo $response | jq .ip)
organization=$(echo $response | jq .org)
city=$(echo $response | jq .city)
region=$(echo $response | jq .region)
country=$(echo $response | jq .country)
location=$(echo $response | jq .loc)
postal=$(echo $response | jq .postal)
timezone=$(echo $response | jq .timezone)



echo -e "\tip            : $ip" >> $results_dir/Domain-reconnaissance/ip_addresses.txt
echo -e "\torganization  : $organization" >> $results_dir/Domain-reconnaissance/ip_addresses.txt
echo -e "\tcity          : $city" >> $results_dir/Domain-reconnaissance/ip_addresses.txt
echo -e "\tregion        : $region" >> $results_dir/Domain-reconnaissance/ip_addresses.txt
echo -e "\tcountry       : $country" >> $results_dir/Domain-reconnaissance/ip_addresses.txt
echo -e "\tpostal        : $postal" >> $results_dir/Domain-reconnaissance/ip_addresses.txt
echo -e "\tlocation      : $location" >> $results_dir/Domain-reconnaissance/ip_addresses.txt
echo -e "\ttimezone      : $timezone" >> $results_dir/Domain-reconnaissance/ip_addresses.txt


echo -e "\n\n" >> $results_dir/Domain-reconnaissance/ip_addresses.txt
cat $results_dir/Domain-reconnaissance/ip_addresses.txt





# -------------------Perform domain reconnaissance------------------

printf "$YLW"
echo -e "\n\n*============{ Domain Reconnaissance }============*\n\n"

# Gather information about subdomains using amass
#subdomains=$(amass enum -d $target -o $results_dir/Domain-reconnaissance/subdomains.txt ) &

# | pv | awk '{printf("%3d%% [%s%s]\r", ($1/$2)*100, str, sp)}{str=str "#";sp=sp " "}'





# Gather IP addresses using dig
printf $CYN
echo "Gathering NS-lookup Details . . . . ."
ip_addresses=$(nslookup $target)
echo "$ip_addresses" > $results_dir/Domain-reconnaissance/nslookup.txt

    printf "${GRN}"
    echo -ne '[|||                       ][20%]\r'
    sleep 2
    echo -ne '[|||||||                   ][40%]\r'
    sleep 1
    echo -ne '[||||||||||||||            ][60%]\r'
    sleep 1
    echo -ne '[|||||||||||||||||||||||   ][80%]\r'
    sleep 2
    echo -ne '[|||||||||||||||||||||||||][100%]\r'
    echo -ne '\n\n'
    echo -e "[*] results saved successfully \n\n"



# Gather DNS records using dig
printf $CYN
echo "Gathering DNS records..."
dns_records=$(dig $target)
echo "$dns_records" > $results_dir/Domain-reconnaissance/dns_records.txt

    printf "${GRN}"
    echo -ne '[|||                       ][20%]\r'
    sleep 2
    echo -ne '[|||||||                   ][40%]\r'
    sleep 1
    echo -ne '[||||||||||||||            ][60%]\r'
    sleep 1
    echo -ne '[|||||||||||||||||||||||   ][80%]\r'
    sleep 2
    echo -ne '[|||||||||||||||||||||||||][100%]\r'
    echo -ne '\n\n'
    echo -e "[*] results saved successfully \n\n"


# Gather WHOIS information using whois
printf $CYN
echo "Gathering WHOIS information..."
whois_information=$(whois $target)
echo "$whois_information" > $results_dir/Domain-reconnaissance/whois_information.txt

    printf "${GRN}"
    echo -ne '[|||                       ][20%]\r'
    sleep 2
    echo -ne '[|||||||                   ][40%]\r'
    sleep 1
    echo -ne '[||||||||||||||            ][60%]\r'
    sleep 1
    echo -ne '[|||||||||||||||||||||||   ][80%]\r'
    sleep 2
    echo -ne '[|||||||||||||||||||||||||][100%]\r'
    echo -ne '\n\n'
    echo -e "[*] results saved successfully \n\n"

# ---------------Domain recon done ------------------




# ----------------GOOGLE DORKS -----------------------
printf "$YLW"
echo -e "\n\n*================{ Google-dorks }===================*\n\n"
base_dork=(
"[*] Open Redirect"
"https://www.google.com/search?q=site:targetdomain%20inurl:redir%20|%20inurl:url%20|%20inurl:redirect%20|%20inurl:return%20|%20inurl:src=http%20|%20inurl:r=http"
"[*] Robot.txt"
"https://www.google.com/search?q=targetdomain+robots.txt"
"[*] Hunt for Password Files"
"https://www.google.com/search?q=site:targetdomain 'password' filetype:doc | filetype:pdf | filetype:docx | filetype:xls | filetype:dat | filetype:log"
"[*] Directory Listing"
"https://www.google.com/search?q=site:targetdomain intitle:index.of  | 'parent directory'"
"[*] Database Dork"
"https://www.google.com/search?q=site:targetdomain intext:'sql syntax near' | intext:'syntax error has occurred' | intext:'incorrect syntax near' | intext:'unexpected end of SQL command' | intext:'Warning: mysql_connect()' | intext:'Warning: mysql_query() | intext:'Warning: pg_connect()' | filetype:sqlext:sql | ext:dbf | ext:mdb"
"[*] Config and log files"
"https://www.google.com/search?q=site:targetdomain ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini | ext:log"
"[*] Backup Files"
"https://www.google.com/search?q=site:targetdomain ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup"
"[*] Login pages"
"https://www.google.com/search?q=site:targetdomain inurl:login | inurl:signin | intitle:Login | intitle: signin | inurl:auth"
"[*] PHP Infor"
"https://google.com/search?q=site:targetdomain ext:php intitle:phpinfo 'published by the PHP Group'"
"[*] Github Dork"
"https://github.com/search?q=targetdomain"
"[*] Subdomain Enumeraiton Dork"
"https://google.com/search?q=site:*.targetdomain"
"[*] Reverse IP Lookup "
"https://viewdns.info/reverseip/?host=targetdomain&t=1"
"[*] cert.sh check!"
"https://crt.sh/?q=targetdomain"
"[*] Dork for aws s3 buckets"
"https://google.com/search?q=site:.s3.amazonaws.com 'targetdomain'"
"[*] Stackoverflow Dork"
"https://google.com/search?q=site:stackoverflow.com 'targetdomain'"
"[*] pastbin lookup"
"https://google.com/search?q=site:pastebin.com | site:paste2.org | site:pastehtml.com | site:slexy.org | site:snipplr.com | site:snipt.net | site:textsnip.com | site:bitpaste.app | site:justpaste.it | site:heypasteit.com | site:hastebin.com | site:dpaste.org | site:dpaste.com | site:codepad.org | site:jsitor.com | site:codepen.io | site:jsfiddle.net | site:dotnetfiddle.net | site:phpfiddle.org | site:ide.geeksforgeeks.org | site:repl.it | site:ideone.com | site:paste.debian.net | site:paste.org | site:paste.org.ru | site:codebeautify.org  | site:codeshare.io | site:trello.com 'targetdomain'"
"[*] What CMS? check!"
"https://whatcms.org/?s=targetdomain"
"[*] WP-Content DORK"
"https://google.com/search?q=site:targetdomain inurl:wp- | inurl:wp-content | inurl:plugins | inurl:uploads | inurl:themes | inurl:download"
"[*] Web archive!"
"http://wwwb-dedup.us.archive.org:8083/cdx/search?url=targetdomain/&matchType=domain&collapse=digest&output=text&fl=original,timestamp&filter=urlkey:.*wp[-].*&limit=1000000&xx="
"[*] Wordpress Deep search"
"https://google.com/search?q=site:targetdomain inurl:php?=id1 | inurl:index.php?id= | inurl:pageid= | inurl:.php?"
"[*] SSL Server Test"
"https://www.ssllabs.com/ssltest/analyze.html?d=targetdomain"
"[*] wayback machine"
"https://web.archive.org/web/*/targetdomain/*"
"[*] SHODAN Search"
"https://www.shodan.io/search?query=targetdomain"
"[*] search in grep.app"
"https://grep.app/search?q=targetdomain"
"[*] security Headers"
"https://securityheaders.com/?q=targetdomain&followRedirects=on"
)
printf $BLU
counter=0
for dork in "${base_dork[@]}"; do
  new_dork=$(echo $dork | sed "s/targetdomain/$target/g")
  echo "$new_dork" >> $results_dir/Google-dorks/google-dorks.txt
  counter=$((counter+1))
  if [ $counter -eq 2 ]; then
    echo "" >> $results_dir/Google-dorks/google-dorks.txt
    counter=0
  fi
done

cat $results_dir/Google-dorks/google-dorks.txt





# ---------------Vulnerability Scanning ------------------
printf $YLW
echo -e "\n\n*============{ Vulnerability Scanning }============*\n\n"
headers=$(curl -s -I $target)
printf $RED
echo "Vulnerability Scan Report for $target" > $results_dir/Vulnerability-scanning/scan-results.txt
echo "----------------------------------------------------------------" >> $results_dir/Vulnerability-scanning/scan-results.txt
echo "" >> $results_dir/Vulnerability-scanning/scan-results.txt

echo "Checking for X-XSS-Protection "
if echo "$headers" | grep -q "X-XSS-Protection: 1; mode=block"; then
  echo "X-XSS-Protection header found." >> $results_dir/Vulnerability-scanning/scan-results.txt
else
  echo "[!] X-XSS-Protection header not found." >> $results_dir/Vulnerability-scanning/scan-results.txt
  echo "[#] Possible vulnerability: Cross-Site Scripting (XSS)" >> $results_dir/Vulnerability-scanning/scan-results.txt
fi

echo "Checking for X-Content-Type-Options "
if echo "$headers" | grep -q "X-Content-Type-Options: nosniff"; then
  echo "X-Content-Type-Options header found." >> $results_dir/Vulnerability-scanning/scan-results.txt
else
  echo "[!] X-Content-Type-Options header not found." >> $results_dir/Vulnerability-scanning/scan-results.txt
  echo "[#] Possible vulnerability: MIME-Type Misconfiguration" >> $results_dir/Vulnerability-scanning/scan-results.txt
fi

echo "Checking for X-Frame-Options"
if echo "$headers" | grep -q "X-Frame-Options: (DENY|SAMEORIGIN)"; then
  echo "X-Frame-Options header found." >> $results_dir/Vulnerability-scanning/scan-results.txt
else
  echo "[!] X-Frame-Options header not found." >> $results_dir/Vulnerability-scanning/scan-results.txt
  echo "[#] Possible vulnerability: Clickjacking" >> $results_dir/Vulnerability-scanning/scan-results.txt
fi

echo "Checking for Strict-Transport-Security "
if echo "$headers" | grep -q "Strict-Transport-Security: max-age="; then
  echo "Strict-Transport-Security header found." >> $results_dir/Vulnerability-scanning/scan-results.txt
else
  echo "[!] Strict-Transport-Security header not found." >> $results_dir/Vulnerability-scanning/scan-results.txt
  echo "[#] Possible vulnerability: Man-in-the-middle (MITM) attack" >> $results_dir/Vulnerability-scanning/scan-results.txt
fi

echo "Checking for X-Permitted-Cross-Domain-Policies "
if echo "$headers" | grep -q "X-Permitted-Cross-Domain-Policies: none"; then
  echo "X-Permitted-Cross-Domain-Policies header found." >> $results_dir/Vulnerability-scanning/scan-results.txt
else
  echo "[!] X-Permitted-Cross-Domain-Policies header not found." >> $results_dir/Vulnerability-scanning/scan-results.txt
  echo "[#] Possible vulnerability: Cross-Domain Data Leakage" >> $results_dir/Vulnerability-scanning/scan-results.txt
fi


echo "Checking for Public-Key-Pins"
if echo "$headers" | grep -q "Public-Key-Pins"; then
  echo "Public-Key-Pins header found." >> $results_dir/Vulnerability-scanning/scan-results.txt
else
  echo "[!] Public-Key-Pins header not found." >> $results_dir/Vulnerability-scanning/scan-results.txt
  echo "[#] Possible vulnerability: SSL/TLS Interception" >> $results_dir/Vulnerability-scanning/scan-results.txt
fi

echo "Checking for Feature-Policy"
if echo "$headers" | grep -q "Feature-Policy: "; then
  echo "Feature-Policy header found." >> $results_dir/Vulnerability-scanning/scan-results.txt
else
  echo "[!] Feature-Policy header not found." >> $results_dir/Vulnerability-scanning/scan-results.txt
  echo "[#] Possible vulnerability: Feature Policy misconfiguration" >> $results_dir/Vulnerability-scanning/scan-results.txt
fi

echo "Checking for Referrer-Policy"
if echo "$headers" | grep -q "Referrer-Policy: "; then
  echo "Referrer-Policy header found." >> $results_dir/Vulnerability-scanning/scan-results.txt
else
  echo "[!] Referrer-Policy header not found." >> $results_dir/Vulnerability-scanning/scan-results.txt
  echo "[#] Possible vulnerability: Referrer Policy misconfiguration" >> $results_dir/Vulnerability-scanning/scan-results.txt
fi


echo "" >> $results_dir/Vulnerability-scanning/scan-results.txt
echo "Scan completed." >> $results_dir/Vulnerability-scanning/scan-results.txt


printf "${GRN}"
echo -ne '[|||                       ][20%]\r'
sleep 1
echo -ne '[|||||||                   ][40%]\r'
sleep 1
echo -ne '[||||||||||||||            ][60%]\r'
sleep 1
echo -ne '[|||||||||||||||||||||||   ][80%]\r'
sleep 1
echo -ne '[|||||||||||||||||||||||||][100%]\r'
echo -ne '\n\n'
echo -e "[*] results saved successfully \n\n"




# # Perform network mapping using nmap
# echo -e "\n\n*============{ Network Mapping }============*\n\n"
# nmap_network_map=$(nmap -A $target)
# echo "$nmap_network_map" > $results_dir/Network-mapping/nmap_network_map.





# ------------------- Perform application fingerprinting------------

printf $YLW
echo -e "\n\n*========={ Application fingerprinting }=========*\n\n"


# Use lynx to fetch the HTML content of the target domain
content=$(lynx -dump "$target")

# Extract all the URLs from the HTML content using awk
urls=$(echo "$content" | awk '/http/ {print $2}')

# Store the URLs in a text file
echo "$urls" > $results_dir/Application-fingerprinting/endpoints.txt

printf $WHT
echo "Found $(wc -l < $results_dir/Application-fingerprinting/endpoints.txt) endpoints."



printf "${GRN}"
echo -ne '[###                       ][20%]\r'
sleep 1
echo -ne '[#######                   ][40%]\r'
sleep 1
echo -ne '[##############            ][60%]\r'
sleep 1
echo -ne '[#######################   ][80%]\r'
sleep 1
echo -ne '[##########################][100%]\r'
echo -ne '\n\n'
echo -e "[*] Endpoints gathering completed successfully \n\n"





printf $YLW
echo -e "\n\n*========={ Extracting all the links }=========*\n\n"

echo -e "\033[1;32;40m"
echo "                         ............. "
echo "                      ................. "
echo "                    .......        ..... "
echo "                 ........          ..... "
echo "               .......            ...... "
echo "            ***********        ........ "
echo "          ***************    ....... "
echo "       ********......*****........ "
echo "     *******    ............... "
echo "  ********        .......... "
echo " ******            ******* "
echo "******          ******** "
echo " *****        ******* "
echo " ****************** "
echo "   ************* "
echo "    *════════════════════════════════════════════════════════════════*"

echo -e "\033[38;2;255;255;255m"



links=$(curl -sL $target | grep -o '<a href=['"'"'"][^"'"'"']*['"'"'"]' | sed -e 's/<a href=["'"'"']//g' -e 's/["'"'"']//g')

for link in $links
do
  if [[ $link == http* ]]; then
    echo $link >> $results_dir/Application-fingerprinting/alllinks.txt
  else
    echo "$target/$link" >> $results_dir/Application-fingerprinting/alllinks.txt
  fi
done

printf $BLU
echo "Found $(wc -l < $results_dir/Application-fingerprinting/alllinks.txt) Links from the $target."
printf $WHT


wait
cat $results_dir/Application-fingerprinting/technologies.txt

echo -e "\n\n*======{ Ufff!! Hogaya Bhai }======*\n\n"




# # Take screenshots of the target website
# echo "Taking screenshots of the target website..."
# screenshots=$(wkhtmltoimage $target $results_dir/Screenshots/screenshot.png)

# wait

# # Generate a report using all the gathered information
# echo "Generating a report..."
# report="Report for $target\n\n"
# report+="Subdomains:\n$subdomains\n\n"
# report+="IP Addresses:\n$ip_addresses\n\n"
# report+="DNS Records:\n$dns_records\n\n"
# report+="WHOIS Information:\n$whois_information\n\n"
# report+="Port Scanning Results:\n$nmap_output\n\n"
# report+="Vulnerability Scanning Results:\n$openvas_output\n\n"
# report+="Web Application Scanning Results:\n$zap_output\n\n"
# report+="Network Mapping Results:\n$nmap_network_map\n\n"
# report+="Application Fingerprinting Results:\n$nmap_app_fingerprint\n\n"
# report+="Screenshots:\n$results_dir/Screenshots/screenshot.png\n\n"
# echo "$report" > $results_dir/Reporting/report.txt
