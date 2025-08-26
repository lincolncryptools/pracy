#!/usr/bin/bash

# Change to 'MNT159' or 'BN254' to try different curves
CURVE="SS512"

cd /home/pracy/backends/charm
sed -i "s/\"groupObj\": .*/\"groupObj\": \"${CURVE}\",/g" ./CharmBackend/tests/correctness.json
env LD_LIBRARY_PATH="/home/pracy/libs/pbc-0.5.14/lib" python3.9 main.py
