#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <token>"
  exit 1
fi

token="$1"

file="ip.db"

if [ ! -f "$file" ]; then
  echo "Error: File '$file' not found!"
  exit 1
fi

while IFS= read -r ip; do
  curl -s "https://api.ip2location.io/?key=${token}&ip=${ip}&format=json" >> ip2loc.db
done < "$file"

chmod 444 $file
