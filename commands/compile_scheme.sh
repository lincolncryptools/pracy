#!/usr/bin/bash

# Change file to compile a different scheme
SCHEME="/home/pracy/schemes/a_0_oe.json"

# Change to 'charm' to generate code for Charm backend
BACKEND="relic" 

source /home/pracy/venvs/compiler/bin/activate
python -m pracy -b $BACKEND $SCHEME
