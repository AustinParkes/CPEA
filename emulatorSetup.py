#!/usr/bin/env python3

"""
Things to add:
    - Argument parsing when running script.
        1) Elf File 
        2) Verbose Mode to print results
        3) Option to generate a TOML template from scratch, incase original template is messed up.
           Preferably without overwriting original, so original isn't accidently overwritten.

"""

"""
Queries
    1) Does TOML let you insert keys into the middle of a table? 
       Currently re-ordering keys to achieve this illusion.
    
"""
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

def generate_periph(config_file):
                           
    count = 0           # Number of modules we want to generate	
    num_exist = 0       # Number of modules that currently exist in TOML
    index = 0           # Index of modules

    # Load entire TOML as a dictionary
    # Returns TOMLDocument/Dictionary
    config = parse(open(config_file).read())
    
    """
    core and mem_map
    """
    # Update emulator configurations
    # TODO: Drastically modify this so it isn't confusing to read ... 
    
    # TODO: Modify this to add [config] if it doesn't exist
    if config['config']:     # if config['config']['options']:
    
        #options = ["core", "mem_map"]    
        
        update_core(config)
        update_mem_map(config)

    
    # Update mmio table
    if config['mmio']:
        
        # Cycle Peripheral Counts
        for p_count in config['mmio']['count']:
           
            # Get [periph] from [periph]_count
            if p_count.endswith("_count"):
                periph = p_count[:-6]    
            
            else:
                print("ERROR: Naming convention for [mmio.count] keys must be [periph]_count")
                print("       You have: %s" % (p_count))
                quit()
            
            count = config['mmio']['count'][p_count]

            if count < 0:
                continue

            # No more than 16 peripherals of any kind. TODO: This could change :). Need to figure out reasonable counts. 	
            elif count > 16:
                count = 16
                config['mmio']['count'][p_count] = 16
                print("No more than 16 modules allowed. Generating 16.")

            # Check if current peripheral already exists in TOML.				
            num_exist = check_existance(config, periph)
										
            # Peripheral already exists at specified count, so don't update.	
            if count == num_exist:	
                # Check if we need to update register counts before we leave
                # TODO: Will also need to check if flag count has changed.
                update_regs(config, periph, count)					
				
            # Erase the excess peripheral modules
            elif count < num_exist:
                diff = num_exist - count
                print("Deleting %0d %s" % (diff, periph))	
                                
                index = str(num_exist-1)
                while (count < num_exist):
						
                    # Erase peripheral
                    if count == 0:
                        config['mmio'].remove(periph)
                        break
							
                    # Erase modules	
                    else:	
                        config['mmio'][periph].remove(index)
                        index = str( int(index)-1 )
                        num_exist = num_exist - 1
								
                # Check if we need to update register counts before we leave	
                # TODO: Will need to check if flag count has changed	
                update_regs(config, periph, count)									
					
            # Generate more modules TODO: Make this an else statement? idk why it's elif
            elif count > num_exist:	
                diff = count - num_exist
                print("Adding %0d more %s" % (diff, periph))
                	
                # Only indent first instance. Don't overwrite existing modules
                if num_exist == 0:
                    config['mmio'][periph] = table()
                    config['mmio'][periph].indent(4)
					
                # Generate as many modules as 'count' specifies
                for i in range(num_exist, count):
                    generate_module(config, periph, i)
							
                # Check if we need to update register counts before we leave
                update_regs(config, periph, count)
						
        # Check if any peripherals exist which are no longer under [mmio.count]
        check_existance(config, 0)
						
    # Write to TOML
    config = dumps(config)
	
    # Remove unwanted quotations from around hexadecimal vlaues
    parsed_config = del_quotes(config)

    #print(parsed_config)        
    with open(config_file, 'w') as f:
        f.write(parsed_config)


def update_core(config):
    
    core = config['config']['core']
    
    # Ensure core options have acceptable values
    if 'core' in config['config']:
        # Check all "core" config boundaries
        if core['cpu_model'] not in arm_cpus:
            print("ERROR: Must use a supported CPU model. You used %s" % (core['cpu_model']))
            print("Supported models can be seen with -s [--support] option")
            quit()
                        
        # Ideally, this never gets executed due to first check.    
        elif len(core['cpu_model']) > 19:
            print("ERROR: CPU string too long. Must be less than 20 characters.")
            quit()     

                        
        # TODO: Find an upper limit for num_irq    
        elif core['num_irq'] < 0 or core['num_irq'] > 480:    
            print("ERROR: [config.core.num_irq] must be in range [0, 480]")
            quit() 

        elif core['bitband'] < 0 or core['bitband'] > 1:    
            print("ERROR: [config.core.bitband] must be a boolean value (0 or 1)")
            quit()
            
    # Generate default core options
    if 'core' not in config['config']:
        print("yo")
        config['config'].update({'core': {'cpu_model': "none",
                                          'num_irq': 480,
                                          #'sVTOR': hex(0),   # Unused
                                          'bitband': 0
                                          #'idau': 1          # Unused
                                          }})
        #core.indent(4)                
   
def update_mem_map(config):

    mem_map = config['config']['mem_map']
    
    # Perform basic mem_map boundary checks
    if 'mem_map' in config['config']:
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

# Generates a default template for a peripheral module
def generate_module(config, periph, i):

    mod_i = str(i)
    
    # Generate config table
    config['mmio'][periph].update({mod_i: {'config': {'peripheral_type': "default", 
                                                    'CR_count': 2, 
                                                    'SR_count': 2, 
                                                    'DR_count': 2, 
                                                    'flag_count': 2}}})
    
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

    # Generate interrupt table
    config['mmio'][periph][mod_i].update({'interrupts': {}})
    config['mmio'][periph][mod_i]['interrupts'].indent(4)
					
    # Generate flag table											   
    config['mmio'][periph][mod_i].update({'flags': {}})
    config['mmio'][periph][mod_i]['flags'].indent(4)

    # Add 2 default flag tables
    config['mmio'][periph][mod_i]['flags'].add("Flag1", inline_table())
    config['mmio'][periph][mod_i]['flags']["Flag1"].append('reg', "reg")
    config['mmio'][periph][mod_i]['flags']["Flag1"].append('bit', 0)
    config['mmio'][periph][mod_i]['flags']["Flag1"].append('val', 1)
    config['mmio'][periph][mod_i]['flags']["Flag1"].append('addr', "optional")
    
    config['mmio'][periph][mod_i]['flags'].add("Flag2", inline_table())
    config['mmio'][periph][mod_i]['flags']["Flag2"].append('reg', "reg")
    config['mmio'][periph][mod_i]['flags']["Flag2"].append('bit', 0)
    config['mmio'][periph][mod_i]['flags']["Flag2"].append('val', 1)
    config['mmio'][periph][mod_i]['flags']["Flag2"].append('addr', "optional")    


# Check if peripheral already exists in TOML and how many.
def check_existance(config, periph):

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
    
    # 0 provided: Check if [periph] exists when its [periph]_count does not exist    
    else:  
        del_list = []   # Keep list of existing peripherals to delete   	
        for existing in config['mmio']:
            if existing != "count":
                p_count = existing + "_count"
                
                # Add the peripheral to deletion list if its [periph]_count missing
                if p_count not in config['mmio']['count']:
                    #print("Doesn't exist anymore: ", end = "")
                    #print(existing)
                    del_list.append(existing)
        
        # Delete periphs
        for periph in del_list:
            config['mmio'].remove(periph)                
                
                    
"""
Updates register counts in toml
"""
def update_regs(config, periph, count):
	
    CR_count = 0	# Number of CR that we want to generate
    SR_count = 0	# Number of SR that we want to generate
    DR_count = 0	# Number of DR that we want to generate
    flag_count = 0  # Numer of flags that we want to generate
    
    CR_exist = 0    # Number of CR that already exist in TOML
    SR_exist = 0	# Number of SR that already exist in TOML
    DR_exist = 0	# Number of DR that already exist in TOML
    flag_exist = 0  # Number of flags that already exist in TOML
	
    # Read peripheral configurations for each module	
    for i in range(count):
        mod_i = str(i)
		
        config_tab = config['mmio'][periph][mod_i]['config']	        
        addr_tab = config['mmio'][periph][mod_i]['addr']
        reset_tab = config['mmio'][periph][mod_i]['reset']	
        flag_tab = config['mmio'][periph][mod_i]['flags']
        
        CR_count = config_tab['CR_count']		
        SR_count = config_tab['SR_count']
        DR_count = config_tab['DR_count']	
        flag_count = config_tab['flag_count']
        	
        CR_exist = 0
        SR_exist = 0
        DR_exist = 0
        flag_exist = 0
        
        # Cycle through register addresses, counting the CR, SR and DR.
        for addr_i in addr_tab:			
            if "CR" in addr_i:
                CR_exist = CR_exist + 1
            elif "DR" in addr_i:
                DR_exist = DR_exist + 1
            elif "SR" in addr_i:
                SR_exist = SR_exist + 1 
        
        # Cycle through flags, counting them
        for flag_i in flag_tab:
            flag_exist = flag_exist + 1              

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

        # Nothing to update
        if flag_count == flag_exist:
            pass
        
        # Delete excess flags    
        elif flag_count < flag_exist: 
            print("Deleting %0d %s.%s flags" % (flag_exist-flag_count, periph, mod_i))
            del_flag(config_tab, flag_tab, flag_count, flag_exist)
            
        # Add additional flags
        elif flag_count > flag_exist:
            add_flag(config_tab, flag_tab, flag_count, flag_exist)       

        

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

# Remove unwanted quotations around hexadecimal values.
def del_quotes(config):

    # Re-write config
    parsed_config = ""

    # IMPORTANT: Add to this list anytime you want to keep quotations on a particular line.    
    #            Otherwise, quotes will be deleted on that line  
    keep_quotes = ["reg", "cpu_model", "irq", "peripheral_type"]
    
    # Re-write line by line
    for line in config.splitlines():
    	
        # Delete quotes.
        if all(key not in line for key in keep_quotes):
            for ch in range(0, len(line)):
                if (line[ch] != "\""):
                    parsed_config = parsed_config + line[ch]
					
            # Add newline.		
            parsed_config = parsed_config + "\n"
			
        # Re-write quotes ONLY if on same line as "reg."		
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
        generate_periph(args.gen_periph)
		
    elif args.extract_elf:
        extract_elf(args.extract_elf)
        
    elif args.document:
        document(args.document)     
    
    elif args.list_types:
        list_types(args.list_types)
        
    elif args.list_arch:
        list_arch(args.list_arch)    
        
