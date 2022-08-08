#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

git clone https://github.com/Gomez0015/CafeScan.git

cd CafeScan

rm -r /usr/share/CafeScan

mkdir /usr/share/CafeScan

mv dicts /usr/share/CafeScan/

chmod +x ./CafeScan

mv ./CafeScan /usr/bin/

cd ..

rm -r CafeScan

echo 'Done!'
