#!/usr/bin/env python3

"""
Things to add:
    - Argument parsing when running script.
        1) Elf File 
        2) Verbose Mode to print results
        3) Option to generate a TOML template from scratch, incase original template is messed up.
           Preferably without overwriting original, so original isn't accidently overwritten.

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

def generate_periph(config_file):

	# TODO: Let someone configure number of flags they want.   
    p_flags = {'f1': "Flag1", 'f2': "Flag2", 'f3': "Flag3",
               'f4': "Flag4", 'f5': "Flag5", 'f6': "Flag6"}
                           
    count = 0           # Number of modules we want to generate	
    num_exist = 0       # Number of modules that currently exist in TOML
    index = 0           # Index of modules

    # Load entire TOML as a dictionary
    # Returns TOMLDocument/Dictionary
    config = parse(open(config_file).read())
    
    # Update emulator configurations
    if config['config']['options']:
    
        options = ["core", "mem_map"]
        
        # Acceptable model names for ARM
        arm_cpus = ["cortex-m4"]
        
        # Cycle options to generate the correct configurations
        for option in options:
        
            # Remove config option
            if config['config']['options'][option] == 0: 
                if option in config['config']:
                    config['config'].remove(option)            
                        
            
            # Config option should exist
            elif config['config']['options'][option] == 1:
                if option not in config['config']:
                
                    # Determine the option we will generate
                    if option == "core":                      
                        config['config'].update({option: {'cpu_model': "cortex-m4",
                                                        'mpu': 1,
                                                        'itm': 1,
                                                        'etm': 1,
                                                        'num_irq': 57,
                                                        'nvic_bits': 4}})
                        config['config'][option].indent(4)
                        
                    elif option == "mem_map":                                         
                        config['config'].update({option: {'flash_base': hex(0x0),
                                                        'flash_size': hex(0x1F40000),
                                                        'sram_base': hex(0x1fff0000),
                                                        'sram_size': hex(0x3E800),
                                                        'sram_base2': hex(0x0),
                                                        'sram_size2': hex(0x0),
                                                        'sram_base3': hex(0x0),
                                                        'sram_size3': hex(0x0)}})
                        config['config'][option].indent(4) 
                
                # Configs already exist. Check if entered values are allowed. 
                # Boundaries may change over time. Just give general boundaries for now.
                else:
                
                    # Determine the option to check
                    if option == "core":
                    
                        # Check all "core" config boundaries
                        if config['config'][option]['cpu_model'] not in arm_cpus:
                            print("ERROR: Must use a supported CPU model. You used %s" % (config['config'][option]['cpu_model']))
                            print("Supported models can be seen with -s [--support] option")
                            quit()
                        
                        # Ideally, this never gets executed due to first check.    
                        elif len(config['config'][option]['cpu_model']) > 19:
                            print("ERROR: CPU string too long. Must be less than 20 characters.")
                            quit()     
                            
                        elif config['config'][option]['mpu'] < 0 or config['config'][option]['mpu'] > 1:    
                            print("ERROR: [config.%s.mpu] must be a boolean value (0 or 1)" % (option))
                            quit()
                            
                        elif config['config'][option]['itm'] < 0 or config['config'][option]['itm'] > 1:    
                            print("ERROR: [config.%s.itm] must be a boolean value (0 or 1)" % (option))
                            quit() 
                            
                        elif config['config'][option]['etm'] < 0 or config['config'][option]['etm'] > 1:    
                            print("ERROR: [config.%s.etm] must be a boolean value (0 or 1)" % (option))
                            quit()
                        
                        # TODO: Find an upper limit for num_irq    
                        elif config['config'][option]['num_irq'] < 0 or config['config'][option]['num_irq'] > 256:    
                            print("ERROR: [config.%s.num_irq] must be in range [0, 256]" % (option))
                            quit() 
                            
                        # TODO: Find limits for nvic_bits   
                        elif config['config'][option]['nvic_bits'] < 0 or config['config'][option]['nvic_bits'] > 1000000:    
                            print("ERROR: [config.%s.nvic_bits] must be in range [0, idk_yet]" % (option))
                            quit()                                                                                          
                    
                    # TODO: Find more appropriate memory limits   
                    # TODO: Make sure memory doesn't overlap? Maybe overlapping is allowed in QEMU ... not sure.  
                    elif option == "mem_map":    
                        if config['config'][option]['flash_base'] < 0 or config['config'][option]['flash_base'] > 0xffffffff:
                            print("ERROR: [config.%s.flash_base] must be in range [0, 0xffffffff]" % (option))
                            quit()
                            
                        elif config['config'][option]['flash_size'] < 0 or config['config'][option]['flash_size'] > 0x20000000:
                            print("ERROR: [config.%s.flash_size] must be in range [0, 0x20000000]" % (option))
                            quit()   
                        
                        elif config['config'][option]['sram_base'] < 0 or config['config'][option]['sram_base'] > 0xffffffff:
                            print("ERROR: [config.%s.sram_base] must be in range [0, 0xffffffff]" % (option))
                            quit()  
                            
                        elif config['config'][option]['sram_size'] < 0 or config['config'][option]['sram_size'] > 0xffffffff:
                            print("ERROR: [config.%s.sram_size] must be in range [0, 0x0x20000000]" % (option))
                            quit()
                            
                        elif config['config'][option]['sram_base2'] < 0 or config['config'][option]['sram_base2'] > 0xffffffff:
                            print("ERROR: [config.%s.sram_base2] must be in range [0, 0xffffffff]" % (option))
                            quit()  
                            
                        elif config['config'][option]['sram_size2'] < 0 or config['config'][option]['sram_size2'] > 0xffffffff:
                            print("ERROR: [config.%s.sram_size2] must be in range [0, 0x0x20000000]" % (option))
                            quit()     
                            
                        elif config['config'][option]['sram_base3'] < 0 or config['config'][option]['sram_base3'] > 0xffffffff:
                            print("ERROR: [config.%s.sram_base] must be in range [0, 0xffffffff]" % (option))
                            quit()  
                            
                        elif config['config'][option]['sram_size3'] < 0 or config['config'][option]['sram_size3'] > 0xffffffff:
                            print("ERROR: [config.%s.sram_size] must be in range [0, 0x0x20000000]" % (option))
                            quit()                                                                                                                                                        
                          
                                                                  
            else:
                print("ERROR: [config.options.%s] must be a boolean value (0 or 1)" % (option))         
                quit()
               
    
    # Update mmio table
    if config['mmio']:
        
        # Cycle Peripheral Counts
        for p_count in config['mmio']['count']:
           
            # Get [periph] from [periph]_count
            if p_count.endswith("_count"):
                periph = p_count[:-6]    
            
            # Leave if peripheral naming convention wrong.
            else:
                print("ERROR: Naming convention for [mmio.count] keys must be [periph]_count")
                print("       You have: %s" % (p_count))
                quit()
            
            count = config['mmio']['count'][p_count]

            # SKIP peripheral if invalid number
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
                    generate_module(config, periph, p_flags, i)
							
                # Check if we need to update register counts before we leave
                update_regs(config, periph, count)
						
        # Check if any peripherals exist which are no longer under [mmio.count]
        check_existance(config, 0)
						
		
    #print(config)
    #print(dumps(config))
	
    # Write to TOML
    config = dumps(config)
	
    # Remove unwanted quotations from around hexadecimal vlaues
    parsed_config = del_quotes(config)
		
    #print(parsed_config)
    with open(config_file, 'w') as f:
        f.write(parsed_config)

def generate_module(config, periph, p_flags, i):

    mod_i = str(i)
    # Generate config table
    config['mmio'][periph].update({mod_i: {'config': {'SR_count': 2, 'DR_count': 2}}})
    # TODO: Move the indentations to the end of this.
						
    config['mmio'][periph][mod_i].indent(4)
    config['mmio'][periph][mod_i]['config'].indent(4)					
					
    # Generate addr table
    config['mmio'][periph][mod_i].update({'addr': {'base_addr': hex(0), 'SR1_addr': hex(0), 
													'SR2_addr': hex(0), 'DR1_addr': hex(0), 'DR2_addr': hex(0)}})
					
    config['mmio'][periph][mod_i]['addr'].indent(4)					
									
    # Generate reset table
    config['mmio'][periph][mod_i].update({'reset': {'SR1_reset': hex(0), 'SR2_reset': hex(0), 
													'DR1_reset': hex(0), 'DR2_reset': hex(0)}})
					
    config['mmio'][periph][mod_i]['reset'].indent(4)						
					
    # Generate flag table											   
    config['mmio'][periph][mod_i].update({'flags': {}})
    config['mmio'][periph][mod_i]['flags'].indent(4)

    for flag in p_flags.values():
        config['mmio'][periph][mod_i]['flags'].add(flag, inline_table())
        config['mmio'][periph][mod_i]['flags'][flag].append('reg', "reg")
        config['mmio'][periph][mod_i]['flags'][flag].append('bit', 0)
        config['mmio'][periph][mod_i]['flags'][flag].append('val', 1)
        config['mmio'][periph][mod_i]['flags'][flag].append('addr', "optional")


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
                
                    

def update_regs(config, periph, count):
	
    SR_count = 0	# Number of SR that we want to generate
    DR_count = 0	# Number of DR that we want to generate
	
    SR_exist = 0	# Number of SR that already exist in TOML
    DR_exist = 0	# Number of DR that already exist in TOML
	
    # Read peripheral configurations for each module	
    for i in range(count):
        mod_i = str(i)
		
        p_config = config['mmio'][periph][mod_i]['config']			
        SR_count = p_config['SR_count']
        DR_count = p_config['DR_count']
        addr_tab = config['mmio'][periph][mod_i]['addr']
        reset_tab = config['mmio'][periph][mod_i]['reset']	
		
        # Save the keys for re-ordering SR and DR.	
        addr_keys = list(zip(addr_tab.keys(), addr_tab.values()))
        reset_keys = list(zip(reset_tab.keys(), reset_tab.values()))
		
        SR_exist = 0
        DR_exist = 0
        # Cycle through register addresses, counting the SR and DR.
        for addr_i in config['mmio'][periph][mod_i]['addr']:			
            # Detect SR or DR
            if "SR" in addr_i:
                SR_exist = SR_exist + 1
            elif "DR" in addr_i:
                DR_exist = DR_exist + 1
		
        # Nothing to update
        if SR_count == SR_exist:
            pass
			
        # Delete excess SR	
        elif SR_count < SR_exist:
            del_SR(p_config, addr_tab, reset_tab, SR_count, SR_exist)
		
        # Add additional SR	
        elif SR_count > SR_exist:
            add_SR(p_config, addr_tab, reset_tab, addr_keys, reset_keys, SR_count, SR_exist)								
		
        # Nothing to update, 
        if DR_count == DR_exist:
            pass
			
        # Delete excess DR	
        elif DR_count < DR_exist:
            del_DR(p_config, addr_tab, reset_tab, DR_count, DR_exist)				
		
        # Add additional DR	
        elif DR_count > DR_exist:
            add_DR(p_config, addr_tab, reset_tab, DR_count, DR_exist)		

    return

def add_SR(p_config, addr_tab, reset_tab, addr_keys, reset_keys, SR_count, SR_exist):

    # Save config keys for imposing limits on SR/DR counts
    p_config_keys = list(zip(p_config.keys(), p_config.values()))
	
    # HACK. To change SR_count: Need to remove and add to prevent extra indentation. Also need to re-order DRs.
    if SR_count >= 9:
        SR_count = 8		
        p_config.remove('SR_count')
        p_config.add('SR_count', 8)
        for key in p_config_keys:
            if "DR" in key[0]:
                p_config.remove(key[0])
                p_config.add(key[0], int(key[1]))		
        print("SR count can't exceed 8")
	
    # Add the SR(s)	
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
            # HACK: key[1] (tomkit.items.Integer) causes indentation unless you convert it to int()
            addr_tab.add(key[0], hex(key[1]))
			
    # Remove the DR reset(s) and add back at correct position		
    for key in reset_keys:
        if "DR" in key[0]:					
            reset_tab.remove(key[0])					
            # HACK: key[1] (tomkit.items.Integer) causes indentation unless you convert it to int()
            reset_tab.add(key[0], hex(key[1]))
    return		
	
				
def add_DR(p_config, addr_tab, reset_tab, DR_count, DR_exist):
    if DR_count >= 3:
        DR_count = 2
        # HACK. Need to remove and add to prevent extra indentation.
        p_config.remove('DR_count')
        p_config.add('DR_count', 2)		
        print("DR count must be 0, 1 or 2")
		
    # Add the DR(s)
    while DR_count > DR_exist:
        DR_addr = "DR" + str(DR_exist+1) + "_addr"
        DR_reset = "DR" + str(DR_exist+1) + "_reset"			
        addr_tab.add(DR_addr, hex(0))
        reset_tab.add(DR_reset, hex(0))
        DR_exist = DR_exist + 1			
    return

	
def del_SR(p_config, addr_tab, reset_tab, SR_count, SR_exist):

    # Save config keys for imposing limits on SR/DR counts
    p_config_keys = list(zip(p_config.keys(), p_config.values()))
    if SR_count <= 0:
        SR_count = 1
        # HACK. To change SR_count: Need to remove and add to prevent extra indentation. Also need to re-order DRs.
        p_config.remove('SR_count')
        p_config.add('SR_count', 1)
        for key in p_config_keys:
            if "DR" in key[0]:
                p_config.remove(key[0])
                p_config.add(key[0], int(key[1]))
						
        print("SR count can't go below 1")
	
    # Delete the SR(s)	
    while SR_count < SR_exist:
        SR_addr = "SR" + str(SR_exist) + "_addr"
        SR_reset = "SR" + str(SR_exist) + "_reset"
        addr_tab.remove(SR_addr)
        reset_tab.remove(SR_reset)
        SR_exist = SR_exist - 1
    return	

		
def del_DR(p_config, addr_tab, reset_tab, DR_count, DR_exist):
    if DR_count < 0:
        DR_count = 0
        # HACK. Need to remove and add to prevent extra indentation.
        p_config.remove('DR_count')
        p_config.add('DR_count', 0)	
        print("DR count must be 0, 1 or 2")
		
    # Delete the DR(s)	
    while DR_count < DR_exist:
        DR_addr = "DR" + str(DR_exist) + "_addr"
        DR_reset = "DR" + str(DR_exist) + "_reset"
        addr_tab.remove(DR_addr)
        reset_tab.remove(DR_reset)
        DR_exist = DR_exist - 1
    return		

# Remove unwanted quotations around hexadecimal values.
def del_quotes(config):

    # Re-write config
    parsed_config = ""

    # IMPORTANT: Add to this list anytime you want to keep quotations on a particular line.    
    # Keep quotations on lines these keys appear on
    keep_quotes = ["reg", "cpu_model"]
    
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
# TODO: Can use arm-none-eabi-objcopy -O binary <elf> <bin> instead for ARM ELFs.
#       However, keeping this incase it's needed for other architectures
#       or has other benefits.
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

def list_arch(x):

    # Dict of supported architectures and cpus
    cpu_archs = {'archs': {'arm': {'cpu1': "test_cpu", 
                                   'cpu2': "cortex-m4"},
                          'test_arch': {'cpu1': "test_cpu"}
                          }}

    
    for arch in cpu_archs['archs']:
        print(arch)
        for cpu in cpu_archs['archs'][arch]:
            print("  " + cpu_archs['archs'][arch][cpu])
        

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Setup emulator and configuration file')
    parser.add_argument('-g', '--gen-config',
                        help='Generate peripheral & emulator configurations',
                        metavar='TOML_File',
                        dest='gen_periph')	
	
    parser.add_argument('-e', '--extract-elf',
                        help='Extract FW and emulator info from elf',
                        metavar='ELF_File',
                        dest='extract_elf')
                        
    parser.add_argument('-s', '--support',
                        help='Show supported architectures and CPUs',
                        action='store_true',                            # Hack to provide an argument
                        dest='list_arch')                    
																	
    args = parser.parse_args();

    #print(args)

    if args.gen_periph:
        generate_periph(args.gen_periph)
		
    elif args.extract_elf:
        extract_elf(args.extract_elf)
        
    elif args.list_arch:
        list_arch(args.list_arch)    
        
