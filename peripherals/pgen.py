#!/usr/bin/env python3

import argparse
import subprocess
from tomlkit import parse
from tomlkit import dumps
from tomlkit import integer
from tomlkit import comment
from tomlkit import key
from tomlkit import table
from tomlkit import inline_table
from tomlkit import nl
from tomlkit import ws

"""
 pkey = ["<peripheral_type>", 
         Implemented?, 
         ID, 
         "<path to peripheral's [hardware] and [interrupts] keys>"]
"""

table_path = "ptable.toml"
ptable = parse(open(table_path).read())

toml_path = "peripherals/<peripheral>.toml"

# Create/modify table of peripheral IDs
for i in range(0, 256):

    pkey = "periph" + str(i)
        
    # Ptable index already populated
    if pkey in ptable:
    
        # No peripheral in place 
        if 'default' in ptable[pkey]:
            ptable[pkey] = ["default", False, i, toml_path]
            
        # Peripheral already in place XXX: This is an educated guess
        # XXX: Also, this won't modify a peripheral when we want to modify it.
        #      so keep in mind we have to modify it manually
        else:
           ptype = ptable[pkey][0]
           impl = ptable[pkey][1]
           periph_path = ptable[pkey][3]
           ptable[pkey] = [ptype, impl, i, periph_path]    
            
    # Ptable index not populated        
    else:
        ptable[pkey] = ["default", False, i, toml_path]            

ptable = dumps(ptable)

#print(ptable)  
  
with open(table_path, 'w') as f:
    f.write(ptable)    
    
    
    
    
