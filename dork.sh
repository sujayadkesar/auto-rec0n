#!/bin/bash

source ../auto-recon.sh

# Prompt the user to enter target website name
echo "Enter target website name: "
read target_website

# Replace the domain name with the target website name in the text file
cp links.txt  $results_dir/Domain-reconnaissance/google-dork.txt
sed -i "s/targetdomain/$target_website/g" google-dork.txt 

# Display the contents of the output file using a while loop
while IFS= read -r line; do
  echo "$line"
  echo ""
done < google-dork.txt