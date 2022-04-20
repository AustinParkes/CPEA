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
from elftools.elf.elffile import ELFFile
from elftools.elf.elffile import SymbolTableSection

# Acceptable model names for ARM TODO: Can update this now for supported QEMU cortex-m models
arm_cpus = ["none", "cortex-m4"]

# Update TOML by: 1) generating or 2) removing configurations
def update_toml(config_file):

    # Load entire TOML as a dictionary
    # Returns TOMLDocument/Dictionary
    config = parse(open(config_file).read())

    # Update core, memory, and mmio tables
    update_core(config)
    update_mem_map(config)
    
    # Updates [mmio] sub-tables      
    update_mmio(config)
			
    # Remove <periph> if it has no corresponding <periph>_count
    check_count(config)
						
    # Write to TOML
    config = dumps(config)
	
    # Remove unwanted quotations from around hexadecimal values
    parsed_config = del_quotes(config)
      
    with open(config_file, 'w') as f:
        f.write(parsed_config)

# Check [core] key boundaries
def update_core(config):

    # Ensure core options have acceptable values
    if 'core' in config['config']:
        core = config['config']['core']
        
        # Check all "core" config boundaries
        if core['cpu_model'] not in arm_cpus:
            print("ERROR: Must use a supported CPU model. You used %s" % (core['cpu_model']))
            print("Supported models can be seen with -s [--support] option")
            quit()
                        
        # Ideally, this never gets executed due to first check.    
        elif len(core['cpu_model']) > 19:
            print("ERROR: CPU string too long. Must be less than 20 characters.")
            quit()     
                         
        elif core['num_irq'] < 0 or core['num_irq'] > 480:    
            print("ERROR: [config.core.num_irq] must be in range [0, 480]")
            quit() 

        elif core['bitband'] < 0 or core['bitband'] > 1:    
            print("ERROR: [config.core.bitband] must be a boolean value (0 or 1)")
            quit()
            
    # Generate default core options
    if 'core' not in config['config']:
        config['config'].update({'core': {'cpu_model': "none",
                                          'num_irq': 480,
                                          #'sVTOR': hex(0),   # Unused
                                          'bitband': 0
                                          #'idau': 1          # Unused
                                          }})
        #core.indent(4)                

# Check [mem_map] key boundaries   
def update_mem_map(config):

    # Perform basic mem_map boundary checks
    if 'mem_map' in config['config']:
        mem_map = config['config']['mem_map']
        if mem_map['flash_base'] < 0 or mem_map['flash_base'] > 0xffffffff:
            print("ERROR: [config.mem_map.flash_base] must be in range [0, 0xffffffff]")
            quit()
                            
        elif mem_map['flash_size'] < 0 or mem_map['flash_size'] > 0x20000000:
            print("ERROR: [config.mem_map.flash_size] must be in range [0, 0x20000000]")
            quit()   
                        
        elif mem_map['sram_base'] < 0 or mem_map['sram_base'] > 0xffffffff:
            print("ERROR: [config.mem_map.sram_base] must be in range [0, 0xffffffff]")
            quit()  
                            
        elif mem_map['sram_size'] < 0 or mem_map['sram_size'] > 0xffffffff:
            print("ERROR: [config.mem_map.sram_size] must be in range [0, 0x0x20000000]")
            quit()
                            
        elif mem_map['sram_base2'] < 0 or mem_map['sram_base2'] > 0xffffffff:
            print("ERROR: [config.mem_map.sram_base2] must be in range [0, 0xffffffff]")
            quit()  
                            
        elif mem_map['sram_size2'] < 0 or mem_map['sram_size2'] > 0xffffffff:
            print("ERROR: [config.mem_map.sram_size2] must be in range [0, 0x0x20000000]")
            quit()     
                            
        elif mem_map['sram_base3'] < 0 or mem_map['sram_base3'] > 0xffffffff:
            print("ERROR: [config.mem_map.sram_base] must be in range [0, 0xffffffff]")
            quit()  
                            
        elif mem_map['sram_size3'] < 0 or mem_map['sram_size3'] > 0xffffffff:
            print("ERROR: [config.mem_map.sram_size] must be in range [0, 0x0x20000000]")
            quit()  
                
    # Generate default mem_map options
    else:
        config['config'].update({'mem_map': {'flash_base': hex(0x0),
                                          'flash_size': hex(0x0),
                                          'sram_base': hex(0x0),
                                          'sram_size': hex(0x0),
                                          'sram_base2': hex(0x0),
                                          'sram_size2': hex(0x0),
                                          'sram_base3': hex(0x0),
                                          'sram_size3': hex(0x0)}})
                                                        
        #mem_map.indent(4)   

# Updates 1) peripheral module 2) register counts 3) flag counts
def update_mmio(config):
    count = 0           # Number of desired modules
    num_exist = 0       # Number of modules that currently exist in TOML
    index = 0           # Module index 
    
    # Peripheral table containing IDs
    table_path = "peripherals/ptable.toml"    
    ptable = parse(open(table_path, 'r').read())
    
    # Cycle Peripheral Counts
    for count_key in config['mmio']['count']:
           
        # Get <periph> name from <periph>_count
        periph = get_periph(count_key)
        
        # User's desired # of <periph> modules
        count = get_count(config, count_key)

        # User's existing # of <periph> modules				
        num_exist = count_existing(config, periph)

        # No module updates
        if count == num_exist:
            pass

        # Generate more peripheral modules
        elif count > num_exist:
            add_peripherals(config, periph, count, num_exist)
							
        # Remove excess peripheral modules
        else:
            del_peripherals(config, periph, count, num_exist)																

		# Update register counts for existing <periph> modules
        update_regs(config, periph, count)
        
        # Update flag counts for existing <periph> modules
        update_flags(config, periph, count)              

        # Update [hardware] & [interrupts] tables for existing <periph> modules
        update_hw_intr(config, ptable, periph, count)


    return

# Gets <periph> name given its key: <periph>_count
def get_periph(count_key):
    if count_key.endswith("_count"):
        periph = count_key[:-6]    
        
    else:
        print("ERROR: Naming convention for [mmio.count] keys must be [periph]_count")
        print("       You have: %s" % (count_key))
        quit()

    return periph
    
# Gets user's desired <periph> count given the key: <periph>_count 
def get_count(config, count_key):
    # User's desired number of <periph> modules 
    count = config['mmio']['count'][count_key]

    # Count must be >= 0 
    if count < 0:
        print("ERROR:")
        print("[mmio.count.%s]: Value must be 0 or greater" % (count_key))
        print("You gave %0d" % (count))
        quit()

    # No more than 16 peripherals of any kind.
    # TODO: Settle on a max count	
    elif count > 16:
        count = 16
        config['mmio']['count'][count_key] = 16
        print("[mmio.count.%s]: No more than 16 modules allowed. Generating 16." % (count_key)) 
   
    return count
            
# Count # of existing <periph> modules already in TOML
def count_existing(config, periph):

    # Check if arg is non-zero
    if periph:
    
        # Check if peripheral already exists in TOML.    
        if periph in config['mmio']:
        				
            #Get the number that exist already.
            for exist_i in config['mmio'][periph]:
                index = exist_i		
	
            num_exist = int(index) + 1  
            return num_exist
            
        # If no match is made, periph doesn't exist.
        else:
            return 0                                          

# Add user's desired # of peripheral modules
def add_peripherals(config, periph, count, num_exist):
    diff = count - num_exist
    print("Adding %0d more %s" % (diff, periph))
                	
    # Only indent first instance. Don't overwrite existing modules
    if num_exist == 0:
        config['mmio'][periph] = table()
        config['mmio'][periph].indent(4)
			
    # Generate peripheral modules
    for i in range(num_exist, count):
        generate_module(config, periph, i)

# Del user's desired # of peripheral modules
def del_peripherals(config, periph, count, num_exist):
    diff = num_exist - count
    print("Deleting %0d %s" % (diff, periph))	
                        
    index = str(num_exist-1)
    while (count < num_exist):
				
        # Remove peripheral
        if count == 0:
            config['mmio'].remove(periph)
            break
					
        # Remove modules	
        else:	
            config['mmio'][periph].remove(index)
            index = str( int(index)-1 )
            num_exist = num_exist - 1
            
            
# Update a peripheral's registers given user's desired register counts
def update_regs(config, periph, count):
	
    CR_count = 0	# Number of CR that we want to generate
    SR_count = 0	# Number of SR that we want to generate
    DR_count = 0	# Number of DR that we want to generate
    
    CR_exist = 0    # Number of CR that already exist in TOML
    SR_exist = 0	# Number of SR that already exist in TOML
    DR_exist = 0	# Number of DR that already exist in TOML
	
    # Read peripheral configurations for each module	
    for i in range(count):
        mod_i = str(i)
		
        config_tab = config['mmio'][periph][mod_i]['config']	        
        addr_tab = config['mmio'][periph][mod_i]['addr']
        reset_tab = config['mmio'][periph][mod_i]['reset']	
        
        CR_count = config_tab['CR_count']		
        SR_count = config_tab['SR_count']
        DR_count = config_tab['DR_count']	
        
        if CR_count < 0:
            print("[mmio.%s.%s.config]: CR_count can't go below 0" % (periph, mod_i))
            print("You gave: %0d" % (CR_count))
            quit()
            
        elif SR_count < 0:
            print("[mmio.%s.%s.config]: SR_count can't go below 0" % (periph, mod_i))
            print("You gave: %0d" % (SR_count))
            quit() 
                   
        elif DR_count < 0:
            print("[mmio.%s.%s.config]: DR_count can't go below 0" % (periph, mod_i))
            print("You gave: %0d" % (DR_count))
            quit()   
                 	
        CR_exist = 0
        SR_exist = 0
        DR_exist = 0
        
        # Cycle through register addresses, counting the CR, SR and DR.
        for addr_i in addr_tab:			
            if "CR" in addr_i:
                CR_exist = CR_exist + 1
            elif "DR" in addr_i:
                DR_exist = DR_exist + 1
            elif "SR" in addr_i:
                SR_exist = SR_exist + 1             

        # Nothing to update
        if CR_count == CR_exist:
            pass
			
        # Delete excess CR	
        elif CR_count < CR_exist:
            print("Deleting %0d [%s.%s] CRs" % (CR_exist - CR_count, periph, mod_i))
            del_CR(config_tab, addr_tab, reset_tab, CR_count, CR_exist)
		
        # Add additional CR	
        elif CR_count > CR_exist:
            print("Adding %0d [%s.%s] CRs" % (CR_count - CR_exist, periph, mod_i))
            add_CR(config_tab, addr_tab, reset_tab, CR_count, CR_exist)
		
        # Nothing to update
        if SR_count == SR_exist:
            pass
			
        # Delete excess SR	
        elif SR_count < SR_exist:
            print("Deleting %0d [%s.%s] SRs" % (SR_exist - SR_count, periph, mod_i))
            del_SR(config_tab, addr_tab, reset_tab, SR_count, SR_exist)
		
        # Add additional SR	
        elif SR_count > SR_exist:
            print("Adding %0d [%s.%s] SRs" % (SR_count - SR_exist, periph, mod_i))
            add_SR(config_tab, addr_tab, reset_tab, SR_count, SR_exist)								
		
        # Nothing to update, 
        if DR_count == DR_exist:
            pass
			
        # Delete excess DR	
        elif DR_count < DR_exist:
            print("Deleting %0d [%s.%s] DRs" % (DR_exist-DR_count, periph, mod_i))
            del_DR(config_tab, addr_tab, reset_tab, DR_count, DR_exist)				
		
        # Add additional DR	
        elif DR_count > DR_exist:
            print("Adding %0d [%s.%s] DRs" % (DR_count - DR_exist, periph, mod_i))
            add_DR(config_tab, addr_tab, reset_tab, DR_count, DR_exist)		    
        

    return

# Add additional CRs while preserving order of CRs, SRs, and DRs
"""
    Note on re-ordering:
    
    When adding a CR, it will naturally be placed at the end of the table.
    We must re-order the other registers so that they come after the CR to
    maintain the vertical order CR, SR, DR 
    
    The same must be done in add_SR to maintain order, but not in add_DR since 
    added DRs goes at the end where they belong.
    
    We achieve this by removing the other registers and adding them back in the correct order.
    We add them back WITH the hex() function so they appear as hexadecimal values in TOML.
    (hex() produces a hex string but we remove the string quotations with del_quotes() )
    DO NOT use this hex function to re-order registers in add_SR because the values will 
    already be in hex string format from add_CR's re-ordering.
    
    Additional quirks:
    
"""   
def add_CR(config_tab, addr_tab, reset_tab, CR_count, CR_exist):

    # Save keys order for re-ordering registers later
    config_keys = list(zip(config_tab.keys(), config_tab.values()))
    addr_keys = list(zip(addr_tab.keys(), addr_tab.values()))
    reset_keys = list(zip(reset_tab.keys(), reset_tab.values()))


    if CR_count > 20:
        CR_count = 20       
        config_tab['CR_count'] = CR_count
        config_tab['CR_count'].indent(4)
        print("CR count can't exceed 20")

	                          	               
    # Add CR(s) in addr and reset tables.
    while CR_count > CR_exist:
        CR_addr = "CR" + str(CR_exist+1) + "_addr"
        CR_reset = "CR" + str(CR_exist+1) + "_reset"			
        addr_tab.add(CR_addr, hex(0))
        reset_tab.add(CR_reset, hex(0))
        CR_exist = CR_exist + 1	
        
    # Remove the SR addr(s) and add back at correct position
    for key in addr_keys:
        if "SR" in key[0]:
            addr_tab.remove(key[0])
            addr_tab.add(key[0], hex(key[1]))
           
    # Remove the SR reset(s) and add back at correct position
    for key in reset_keys:
        if "SR" in key[0]:
            reset_tab.remove(key[0])
            reset_tab.add(key[0], hex(key[1]))
            
    # Remove the DR addr(s) and add back at correct position
    for key in addr_keys:
        if "DR" in key[0]:
            addr_tab.remove(key[0])
            addr_tab.add(key[0], hex(key[1]))
         	
    # Remove the DR reset(s) and add back at correct position
    for key in reset_keys:
        if "DR" in key[0]:
            reset_tab.remove(key[0])
            reset_tab.add(key[0], hex(key[1]))
        
    return

# Add additional SRs while preserving order of CRs, SRs, and DRs
"""
    Note on re-ordering:
    
    When adding a SR, it will naturally be placed at the end of the table.
    We must re-order the other registers so that they maintain the vertical 
    order CR, SR, DR.
     
    CRs will already be in correct position, so we are really 
    swapping SRs and DRs here.
    
    Re-ordering is also done in add_CR but not in add_DR.    
    See add_CR for full explanation.
    
    We DO NOT use the hex() function in add_SR to re-order SRs and DRs because
    they have already been placed in hex string format in add_CR 
    
    Additional quirks:
    The DRs need to be indented after re-ordering to maintain their
    original indention. Not quite sure why this is the case here since it
    isn't the case in the other add_xx() functions. 
    
"""      
def add_SR(config_tab, addr_tab, reset_tab, SR_count, SR_exist):

    # Save keys order for re-ordering registers later
    config_keys = list(zip(config_tab.keys(), config_tab.values()))
    addr_keys = list(zip(addr_tab.keys(), addr_tab.values()))
    reset_keys = list(zip(reset_tab.keys(), reset_tab.values()))
        
    # HACK. To change SR_count: Need to remove and add to prevent extra indentation. Also need to re-order DRs.
    if SR_count > 20:
        SR_count = 20		       
        config_tab['SR_count'] = SR_count
        config_tab['SR_count'].indent(4)
        print("SR count can't exceed 20")
	
    # Add the SR(s) in addr and reset tables	
    while SR_count > SR_exist:		
        SR_addr = "SR" + str(SR_exist+1) + "_addr"
        SR_reset = "SR" + str(SR_exist+1) + "_reset"			
        addr_tab.add(SR_addr, hex(0))
        reset_tab.add(SR_reset, hex(0))
        SR_exist = SR_exist + 1		
	
    # Remove the DR addr(s) and add back at correct position
    for key in addr_keys:
        if "DR" in key[0]:	
            addr_tab.remove(key[0])					
            addr_tab.add(key[0], key[1])
            addr_tab[key[0]].indent(4)
			
    # Remove the DR reset(s) and add back at correct position		
    for key in reset_keys:
        if "DR" in key[0]:					
            reset_tab.remove(key[0])					
            reset_tab.add(key[0], key[1])
            reset_tab[key[0]].indent(4)
            
    return

# Add DRs to addr and reset tables.
"""
    Note on re-ordering:
    
    DRs don't need re-ordered! Since they are naturally going to the
    end of the table where they belong.
    
""" 				
def add_DR(config_tab, addr_tab, reset_tab, DR_count, DR_exist):

    if DR_count > 2:
        DR_count = 2   
        config_tab['DR_count'] = DR_count
        config_tab['DR_count'].indent(4)  		
        print("DR count must be 0, 1 or 2")
	
    # Add the DR(s)
    while DR_count > DR_exist:
        DR_addr = "DR" + str(DR_exist+1) + "_addr"
        DR_reset = "DR" + str(DR_exist+1) + "_reset"			
        addr_tab.add(DR_addr, hex(0))
        reset_tab.add(DR_reset, hex(0))      
        DR_exist = DR_exist + 1	
        		
    return

def del_CR(config_tab, addr_tab, reset_tab, CR_count, CR_exist):
    
    if CR_count < 0:
        CR_count = 0      
        config_tab['CR_count'] = CR_count
        config_tab['CR_count'].indent(4)    
        print("CR count can't go below 0")
        
    # Delete the CR(s)	
    while CR_count < CR_exist:
        CR_addr = "CR" + str(CR_exist) + "_addr"
        CR_reset = "CR" + str(CR_exist) + "_reset"
        addr_tab.remove(CR_addr)
        reset_tab.remove(CR_reset)
        CR_exist = CR_exist - 1        
          
    return
	
def del_SR(config_tab, addr_tab, reset_tab, SR_count, SR_exist):

    # Save config key order for re-ordering later
    config_keys = list(zip(config_tab.keys(), config_tab.values()))
    
    if SR_count < 0:
        SR_count = 0
        config_tab['SR_count'] = SR_count
        config_tab['SR_count'].indent(4)		
        print("SR count can't go below 0")
	
    # Delete the SR(s)	
    while SR_count < SR_exist:
        SR_addr = "SR" + str(SR_exist) + "_addr"
        SR_reset = "SR" + str(SR_exist) + "_reset"
        addr_tab.remove(SR_addr)
        reset_tab.remove(SR_reset)
        SR_exist = SR_exist - 1
    return	

		
def del_DR(config_tab, addr_tab, reset_tab, DR_count, DR_exist):
    if DR_count < 0:
        DR_count = 0    
        config_tab['DR_count'] = DR_count
        config_tab['DR_count'].indent(4)                   
        print("DR count must be 0, 1 or 2")
		
    # Delete the DR(s)	
    while DR_count < DR_exist:
        DR_addr = "DR" + str(DR_exist) + "_addr"
        DR_reset = "DR" + str(DR_exist) + "_reset"
        addr_tab.remove(DR_addr)
        reset_tab.remove(DR_reset)
        DR_exist = DR_exist - 1
    return	

# Update flag counts based on user's key input
def update_flags(config, periph, count):

    flag_count = 0  # User's desired # of flags
    flag_exist = 0  # Existing # of flags
    
    # Read flag configurations for each module	
    for i in range(count):
    
        mod_i = str(i)
        config_tab = config['mmio'][periph][mod_i]['config']
        flag_tab = config['mmio'][periph][mod_i]['flags']	
        flag_count = config_tab['flag_count']
        flag_exist = 0
        
        # Cycle through flags, counting them
        for flag_i in flag_tab:
            flag_exist = flag_exist + 1                      

        if flag_count < 0:
            print("[mmio.%s.%s.config]: flag_count can't go below 0" % (periph, mod_i))
            print("You gave: %0d" % (flag_count))
            quit()
            
        # Nothing to update
        if flag_count == flag_exist:
            pass
        
        # Delete excess flags    
        elif flag_count < flag_exist: 
            print("Deleting %0d [%s.%s] flags" % (flag_exist-flag_count, periph, mod_i))
            del_flag(config_tab, flag_tab, flag_count, flag_exist)
            
        # Add additional flags
        elif flag_count > flag_exist:
            print("Adding %0d [%s.%s] flags" % (flag_count - flag_exist, periph, mod_i))
            add_flag(config_tab, flag_tab, flag_count, flag_exist)       
        

    return    

# Add flag(s) to a <periph> module's [flags] table
def add_flag(config_tab, flag_tab, flag_count, flag_exist):

    if (flag_count > 32):
        flag_count = 32
        config_tab['flag_count'] = flag_count
        config_tab['flag_count'].indent(4)
        print("Flag count can't exceed 32")
    
    # Add the flag(s)
    while flag_count > flag_exist:
        flag = "Flag" + str(flag_exist+1)
        flag_tab.add(flag, inline_table())
        flag_tab[flag].append('reg', "reg")   
        flag_tab[flag].append('bit', 0)  
        flag_tab[flag].append('val', 1)  
        flag_tab[flag].append('addr', "optional")  
        flag_exist = flag_exist + 1
        
    return	

# Delete flag(s) from a <periph> module's [flags] table
def del_flag(config_tab, flag_tab, flag_count, flag_exist):
    if flag_count < 0:
        flag_count = 0
        config_tab['flag_count'] = flag_count
        config_tab['flag_count'].indent(4)
        print("Flag count can't go below 0")
        
    # Delete the Flag(s)
    while flag_count < flag_exist:
        flag = "Flag" + str(flag_exist)
        flag_tab.remove(flag)
        flag_exist = flag_exist - 1    
        
    return

"""
    Goal here:
    1) Read from another toml file the full table of peripherals and IDs
       (e.g. periph0 = ["default", true, 0]
             periph1 = ["uart", true, 1]
       )
    2) Search to find a match with the periph_type parsed
    3) If there is a match, autogenerate for that implementation
    
    Questions
    3) Where will that peripheral's tables be stored?
    
    If the matched peripheral has an implementation, autogenerate for that implementaton    
"""

# Update [hardware] and [interrupts] tables based on user's peripheral_type
def update_hw_intr(config, ptable, periph, count):

    for i in range(count):
    
        mod_i = str(i)            
        config_tab = config['mmio'][periph][mod_i]['config']
        hw_tab = config['mmio'][periph][mod_i]['hardware']
        
        # TODO: Use this to verify and obtain the ID
        periph_type = config_tab['peripheral_type']

        # What's the point!
        if periph_type == "default":    
            return

        # Get the ID index for the peripheral table
        tab_index = get_IDindex(periph_type, periph, mod_i)        
        
        # TODO: 
        """
            1) Auto_generate [hw] & [intr] tables from the matching peripheral
            2) However, must check if given peripheral already has populated [hw] or [intr] table
               - In this case, do nothing and keep the same
            3) Must check if a NEW peripheral_type is given.
               - In this case, we would overwrite the old [hw] & [intr] tables with new peripheral info               
            4) May check if the peripheral is matched more than once ... that's a problem! easy to check!
        """                
        for pkey in ptable:
        
            # Peripheral exists in table
            if periph_type == ptable[pkey][tab_index]:
                print("%s, %0d" % (ptable[pkey][0], ptable[pkey][2]))

    return 

    
# Gets the type of ID for peripheral_type (string or integer)    
def get_IDindex(periph_type, periph, mod_i):

    # Get data type entered for the ID
    if (isinstance(periph_type, int)):
        tab_index = 2
    elif (isinstance(periph_type, str)):
        tab_index = 0
    else:
        print("[mmio.%s.%s.config]: Invalid ID for peripheral_type" % (periph, mod_i))
        print("Data must be a string ID or integer ID")
        quit()
        
    return tab_index   
        
# Generates a default template for a peripheral module
def generate_module(config, periph, i):

    mod_i = str(i)
    
    # Generate config table
    config['mmio'][periph].update({mod_i: {'config': {'peripheral_type': "default", 
                                                    'CR_count': 2, 
                                                    'SR_count': 2, 
                                                    'DR_count': 2, 
                                                    'flag_count': 0}}})
    
    """
    Keep for adding other inline tables
    config['mmio'][periph][mod_i]['config'].add('irq', inline_table())
    config['mmio'][periph][mod_i]['config']['irq'].append('enabled', 0)
    config['mmio'][periph][mod_i]['config']['irq'].append('irqn', "null")
    """
    # TODO: Move the indentations to the end of this.
						
    config['mmio'][periph][mod_i].indent(4)
    config['mmio'][periph][mod_i]['config'].indent(4)					
					
    # Generate addr table
    config['mmio'][periph][mod_i].update({'addr': {'base_addr': hex(0), 'CR1_addr': hex(0), 'CR2_addr': hex(0),
                                                                        'SR1_addr': hex(0), 'SR2_addr': hex(0),                                                                         
                                                                        'DR1_addr': hex(0), 'DR2_addr': hex(0)}})
					
    config['mmio'][periph][mod_i]['addr'].indent(4)					
									
    # Generate reset table
    config['mmio'][periph][mod_i].update({'reset': {'CR1_reset': hex(0), 'CR2_reset': hex(0),
                                                    'SR1_reset': hex(0), 'SR2_reset': hex(0), 
													'DR1_reset': hex(0), 'DR2_reset': hex(0)}})
					
    config['mmio'][periph][mod_i]['reset'].indent(4)						

    # Generate hardware table
    config['mmio'][periph][mod_i].update({'hardware': {}})
    config['mmio'][periph][mod_i]['hardware'].indent(4)    

    # Generate interrupt table
    config['mmio'][periph][mod_i].update({'interrupts': {}})
    config['mmio'][periph][mod_i]['interrupts'].indent(4)
	
	# Generate Interface Table
    config['mmio'][periph][mod_i].update({'interface': {}})
    config['mmio'][periph][mod_i]['interface'].indent(4)	
					
    # Generate flag table											   
    config['mmio'][periph][mod_i].update({'flags': {}})
    config['mmio'][periph][mod_i]['flags'].indent(4)

                           
# Remove <periph> if it has no corresponding <periph>_count             
def check_count(config):
    del_list = []   # Keep list of existing peripherals to delete   	
    for existing in config['mmio']:
        if existing != "count":
            count_key = existing + "_count"
                
            # Add the peripheral to deletion list if its [periph]_count missing
            if count_key not in config['mmio']['count']:
                del_list.append(existing)
        
    # Delete periphs
    for periph in del_list:
        config['mmio'].remove(periph)
    
    return                                
                    

# Remove unwanted quotations around hexadecimal values.
def del_quotes(config):

    # Re-write config
    parsed_config = ""

    # Keep quotations on the same line as any of these keywords
    keep_quotes = ["reg", "cpu_model", "irq", "peripheral_type", "none"
                   "full", "partial", "host", "guest"]
    
    # Re-write line by line
    for line in config.splitlines():
    	
        # Delete quotes.
        if all(key not in line for key in keep_quotes):
            for ch in range(0, len(line)):
                if (line[ch] != "\""):
                    parsed_config = parsed_config + line[ch]
					
            # Add newline.		
            parsed_config = parsed_config + "\n"
			
        # Keep quotes		
        else:
            parsed_config = parsed_config + line + "\n"
	
    return parsed_config
    		

# If using elf file, extract useful FW and Emulator information from elf file
# XXX:  Can use arm-none-eabi-objcopy -O binary <elf> <bin> instead for ARM ELFs.
#       However, keeping this incase this has other benefits
#       Can also just call the above command from this function given an architecture.
def extract_elf(elf):
	# Get emulator and firmware configuration details
    """
    What do I need from ELF File
       - 
    1) We need all of the LOAD segments written into the emulator memory.
    2) 
    3)
    4)
    """
	# Check if elf file was given
    with open(elf, 'rb') as f:     
        f.seek(0)
        if f.read(4) != b"\x7fELF":
            f.seek(0)
            print("File given is not an ELF file.")
            return		
        f.seek(0)
        elffile = ELFFile(f)
		
        # Store Load header info
        load_list = []			# Store lists of load members
        load_mems = []			# Store members for each load header
		
		# Get LOAD segment headers for writing file to emulator memory (and memory map maybe)
        max_vaddr = 0	
        for segment in elffile.iter_segments():	
            header = segment.header				# Get the header dictionary
            #print(header)
            if header['p_type'] == 'PT_LOAD':
                offset = header['p_offset']     # File offset
                v_addr = header['p_vaddr']      
                fsize = header['p_filesz']
                memsz = header['p_memsz']
                flag = header['p_flags']        # Memory permission (RWE)
				
                load_mems = [offset, v_addr, fsize, memsz, flag]
                load_list.append(load_mems)
		
		        # Get max virtual address and memsz
                if v_addr > max_vaddr:
                    max_vaddr = v_addr
                    max_memsz = memsz   

        # Will write to this file            		
        bin_file = bytearray(max_vaddr + max_memsz)
        
        # Load bytes from ELF into firmware file
        for load_seg in load_list:
            offset = load_seg[0]
            v_addr = load_seg[1]
            fsize = load_seg[2]
            
            # Load bytes from ELF into byte array
            f.seek(offset)
            load_bin = f.read(fsize)
            for i, byte in enumerate(load_bin):                                
                bin_file[v_addr + i] = byte
                       
        # SANITY CHECKS: Make sure bin_file has correct ELF contents.
        """
        # .vector 
        v_addr = load_list[0][1]
        print(".vector: ", end = "")
        print(bin_file[v_addr:v_addr + 16])
        # .fcfield
        v_addr = load_list[1][1]
        print(".fcfield: ", end = "")
        print(bin_file[v_addr:v_addr + 16])        
        # .test and .ARM.exidc 
        v_addr = load_list[2][1]
        print(".text: ", end = "")
        print(bin_file[v_addr:v_addr + 16])         
        # .relocate and .bss
        v_addr = load_list[3][1]
        print(".relocate: ", end = "")
        print(bin_file[v_addr:v_addr + 16])         
        # .stack
        v_addr = load_list[4][1]
        print(".stack: ", end = "")
        print(bin_file[v_addr:v_addr + 16])
        # Out of load range 1
        v_addr = 0x8000
        print("Out Of R1: ", end = "")
        print(bin_file[v_addr:v_addr + 16])
        # Out of load range 2
        v_addr = 0x1fff0000
        print("Out Of R2: ", end = "")
        print(bin_file[v_addr:v_addr + 16])
        # Out of load range 3
        v_addr = 0x1fff0200 + 0x150
        print("Out Of R3: ", end = "")
        print(bin_file[v_addr:v_addr + 16])
        """           

    # Generate firmware binary from LOAD segments.
    f = open("firmware.bin", "wb")
    f.write(bin_file)
    f.close
    quit()
	
    # Update toml dictionary with ELF data

    # Load entire TOML as a dictionary
    config = parse(open('emulatorConfig.toml').read())

    # Update flash addr
    config['mem_map']['flash_addr'] = hex(ExecVAddr)
    config['mem_map']['flash_addr'].comment(" Generated by emulatorSetup.py")

    # Update flash size
    config['mem_map']['flash_size'] = hex(emu_mem_size)
    config['mem_map']['flash_size'].comment(" Generated by emulatorSetup.py")

    config['mem_map']['mmio']['reg_count'] = 13

    # Update .text start
    config['firmware']['code']['code_addr'] = hex(TextAddr)
    config['firmware']['code']['code_addr'].comment(" Generated by emulatorSetup.py")

    # .text size determine by emulator at the moment.
    config['firmware']['code']['code_size'] = hex(TextSize)
    config['firmware']['code']['code_size'].comment(" Generated by emulatorSetup.py")

    # Update .data start
    config['firmware']['data']['data_addr'] = hex(DataAddr)
    config['firmware']['data']['data_addr'].comment(" Generated by emulatorSetup.py")

    # .data size determine by emulator at the moment.
    config['firmware']['data']['data_size'] = hex(DataSize)
    config['firmware']['data']['data_size'].comment(" Generated by emulatorSetup.py")

    # Update entry point
    config['firmware']['execution']['entry'] = hex(MainAddr)
    config['firmware']['execution']['entry'].comment(" Generated by emulatorSetup.py")

    # Update exit point (NOT updating since this hasn't been tested to work)
    config['firmware']['execution']['end'] = hex(ExitAddr)
    config['firmware']['execution']['end'].comment(" Generated by emulatorSetup.py")
    
    # Write new configurations to a test TOML file

    # Dumps the .toml file as a string while preserving formatting
    config = dumps(config)
    #print(config)

    stop_index = config.find("[mmio]")
	
    # Get rid of all quotations from the TOML file by re-writing a new block of string without them.
    parsed_config = del_quotes(config)
    print("Check if \'del_quotes\' works correctly. Delete this print statement if it does.")
    #print(parsed_config)

    #with open('emulatorConfig.toml', 'w') as f:
    #	f.write(parsed_config)

# TODO: Work in progress. Just wanted to start it as a reminder.
def document(keyword):
    
    #TODO: Could make this a dict with keyword:index pair where the index 
    #      would lead us to a description of the keyword. 
    #      Perhaps like a switch-case thing
    # List of valid keywords
    valid = ["base_addr"]
    
    if keyword in valid:
        pass
    else:
        print("%s is not a valid keyword" % (keyword))    
        
    
    return 


def list_types(x):

    # TODO: Alphabetize in future
    valid_periphs = ["uart", "gpio", "generic"]
    
    for valid in valid_periphs:
        print(valid)
    

def list_arch(x):

    # Dict of supported architectures and cpus
    cpu_archs = {'archs': {'arm': {'cpu1': "cortex-m0",
                                   'cpu2': "cortex-m1",
                                   'cpu3': "cortex-m3", 
                                   'cpu4': "cortex-m4",
                                   'cpu5': "cortex-m7"},
                                   
                          # TODO: Add the remaining unsupported architectures!         
                          'avr': {'cpu1': "None"}           
                          }}

    
    for arch in cpu_archs['archs']:
        print(arch)
        for cpu in cpu_archs['archs'][arch]:
            print("  " + cpu_archs['archs'][arch][cpu])
        

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Setup emulator configurations')
    parser.add_argument('-g', '--gen-config',
                        help='Generate peripheral & emulator configurations',
                        metavar=('TOML_File'),
                        dest='gen_periph')	
	
    parser.add_argument('-e', '--extract-elf',
                        help='Extract FW and emulator info from elf',
                        metavar='ELF_File',
                        dest='extract_elf')
                        
    parser.add_argument('-d', '--documentation',
                        help='Provide documentation for a TOML keyword',
                        metavar='Keyword',
                        dest='document')                        

    parser.add_argument('-t', '--periph-types',
                        help='Show valid peripheral names',
                        action='store_true',                            # Hack to provide a default argument
                        dest='list_types')   
                        
    parser.add_argument('-s', '--support',
                        help='Show supported architectures and CPUs',
                        action='store_true',                            # Hack to provide a default argument
                        dest='list_arch')                    
																	
    args = parser.parse_args();

    if args.gen_periph:
        update_toml(args.gen_periph)
		
    elif args.extract_elf:
        extract_elf(args.extract_elf)
        
    elif args.document:
        document(args.document)     
    
    elif args.list_types:
        list_types(args.list_types)
        
    elif args.list_arch:
        list_arch(args.list_arch)    
        
