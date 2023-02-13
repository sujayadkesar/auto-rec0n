#!/bin/bash

# Define target URL
target_url=$1

# Check if target URL was provided
if [ -z "$target_url" ]; then
  echo "Please provide a target URL as an argument."
  exit 1
fi

# Use curl to retrieve the website's HTML source code
source_code=$(curl -s "$target_url")

# Check if the website returns a 200 status code
if [ $? -ne 0 ]; then
  echo "Error: Unable to retrieve source code from target URL."
  exit 1
fi

# Check if the website is powered by Apache
if echo "$source_code" | grep -q "Apache"; then
  echo "Web server: Apache"
fi

# Check if the website is powered by Nginx
if echo "$source_code" | grep -q "nginx"; then
  echo "Web server: Nginx"
fi

# Check if the website is powered by IIS
if echo "$source_code" | grep -q "Microsoft-I
