#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

mkdir tmp

cd tmp

git clone https://github.com/Gomez0015/CafeScan.git

cd CafeScan

pip install -r ./requirements.txt

rm -r /usr/share/CafeScan

mkdir /usr/share/CafeScan

mv dicts /usr/share/CafeScan/

chmod +x ./CafeScan

rm /usr/bin/CafeScan

mv ./CafeScan /usr/bin/

cd ../../

rm -r tmp

echo 'Done!'
