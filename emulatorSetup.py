#!/usr/bin/env python3

"""
Things to add:
	- Argument parsing when running script.
		1) Elf File 
		2) Verbose Mode to print results
	
	- See if we ever need to calculate .text or .data size here since emulator currently handles that.
	
	- *** IMPORTANT *** Update exit addr to end of main, or find another suitable last instruction
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
	
	p_flags = {'uart': {'f1': "TX_data_empty", 'f2': "RX_data_full", 'f3': "TX_Complete",
						'f4': "RX_enable_ack", 'f5': "TX_enable_ack"},
			   'gpio': {'f1': "Generic_Flag1", 'f2': "Generic_Flag2", 'f3': "Generic_Flag3"}}
		
	count = 0			# Number of modules we want to generate	
	num_exist = 0		# Number of modules that currently exist in TOML
	index = 0			# Index of modules
		
	# Load entire TOML as a dictionary
	# Returns TOMLDocument/Dictionary
	config = parse(open(config_file).read())
	
	if config['mmio']:
	
		# Cycle Peripheral Counts
		for p_count in config['mmio']['count']:
		
			# Get count of peripherals to generate.
			count = config['mmio']['count'][p_count]
			
			# SKIP peripheral if invalid number
			if count < 0:
				continue
			
			# No more than 16 peripherals of any kind. TODO: This could change :). Need to figure out reasonable counts. 	
			elif count > 16:
				count = 16
				config['mmio']['count'][p_count] = 16
				print("No more than 16 modules allowed. Generating 16.")
			
			# Cycle Peripheral Table, looking for a match.	
			for peri in p_flags:
							
				# Check for Peripheral Table Match w/ Peripheral Count.
				if p_count == peri + "_count":
					
					# Check if current peripheral already exists in TOML.				
					num_exist = check_existance(config, peri)
										
					# Peripheral already exists at specified count, so don't update.	
					if count == num_exist:
					
						# Check if we need to update register counts before we leave
						update_regs(config, peri, count)				
						break		
				
					# Erase the excess peripheral modules
					elif count < num_exist:
						index = str(num_exist-1)
						while (count < num_exist):
						
							# Erase peripheral
							if count == 0:
								config['mmio'].remove(peri)
								break
							
							# Erase modules	
							else:	
								config['mmio'][peri].remove(index)
								index = str( int(index)-1 )
								num_exist = num_exist - 1
								
						# Check if we need to update register counts before we leave		
						update_regs(config, peri, count)									
						break
					
					# Generate more modules
					elif count > num_exist:			
						# Only indent first instance. Don't overwrite existing modules
						if num_exist == 0:
							config['mmio'][peri] = table()
							config['mmio'][peri].indent(4)
					
						# Generate as many modules as 'count' specifies
						for i in range(num_exist, count):
							generate_module(config, peri, p_flags, i)
							
						# Check if we need to update register counts before we leave
						update_regs(config, peri, count)
						

						
		
	#print(config)
	#print(dumps(config))
	
	# Write to TOML
	config = dumps(config)
	
	# Remove unwanted quotations from around hexadecimal vlaues
	parsed_config = del_quotes(config)
		
	#print(parsed_config)
	with open(config_file, 'w') as f:
		f.write(parsed_config)

def generate_module(config, peri, p_flags, i):

	mod_i = str(i)
	# Generate config table
	config['mmio'][peri].update({mod_i: {'config': {'SR_count': 2, 'DR_count': 2}}})
	# TODO: Move the indentations to the end of this.
						
	config['mmio'][peri][mod_i].indent(4)
	config['mmio'][peri][mod_i]['config'].indent(4)					
					
	# Generate addr table
	config['mmio'][peri][mod_i].update({'addr': {'base_addr': hex(0), 'SR1_addr': hex(0), 
													'SR2_addr': hex(0), 'DR1_addr': hex(0), 'DR2_addr': hex(0)}})
					
	config['mmio'][peri][mod_i]['addr'].indent(4)					
									
	# Generate reset table
	config['mmio'][peri][mod_i].update({'reset': {'SR1_reset': hex(0), 'SR2_reset': hex(0), 
													'DR1_reset': hex(0), 'DR2_reset': hex(0)}})
					
	config['mmio'][peri][mod_i]['reset'].indent(4)						
					
	# Generate flag table											   
	config['mmio'][peri][mod_i].update({'flags': {}})
	config['mmio'][peri][mod_i]['flags'].indent(4)
	for flag in p_flags[peri].values():
		config['mmio'][peri][mod_i]['flags'].add(flag, inline_table())
		config['mmio'][peri][mod_i]['flags'][flag].append('reg', "reg")
		config['mmio'][peri][mod_i]['flags'][flag].append('bit', 0)


# Check if peripheral already exists in TOML and how many.
def check_existance(config, peri):
	# Check if peripheral already exists in TOML. 
	for existing in config['mmio']:
		if existing == peri:					
			# Get the number that exist already.
			for exist_i in config['mmio'][existing]:
				index = exist_i		
			# Convert to integer. Get existing count from index.	
			num_exist = int(index) + 1  
			return num_exist
			
	# If no match is made, periph doesn't exist.	
	return 0	


def update_regs(config, peri, count):
	
	SR_count = 0	# Number of SR that we want to generate
	DR_count = 0	# Number of DR that we want to generate
	
	SR_exist = 0	# Number of SR that already exist in TOML
	DR_exist = 0	# Number of DR that already exist in TOML
	
	# Read peripheral configurations for each module	
	for i in range(count):
		mod_i = str(i)
		
		p_config = config['mmio'][peri][mod_i]['config']			
		SR_count = p_config['SR_count']
		DR_count = p_config['DR_count']
		addr_tab = config['mmio'][peri][mod_i]['addr']
		reset_tab = config['mmio'][peri][mod_i]['reset']	
		
		# Save the keys for re-ordering SR and DR.	
		addr_keys = list(zip(addr_tab.keys(), addr_tab.values()))
		reset_keys = list(zip(reset_tab.keys(), reset_tab.values()))
		
		SR_exist = 0
		DR_exist = 0
		# Cycle through register addresses, counting the SR and DR.
		for addr_i in config['mmio'][peri][mod_i]['addr']:			
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
		print("DR count must be 1 or 2")
		
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
	if DR_count <= 0:
		DR_count = 1
		# HACK. Need to remove and add to prevent extra indentation.
		p_config.remove('DR_count')
		p_config.add('DR_count', 1)	
		print("DR count must be 1 or 2")
		
	# Delete the DR(s)	
	while DR_count < DR_exist:
		DR_addr = "DR" + str(DR_exist) + "_addr"
		DR_reset = "DR" + str(DR_exist) + "_reset"
		addr_tab.remove(DR_addr)
		reset_tab.remove(DR_reset)
		DR_exist = DR_exist - 1
	return		

		
# TODO: Add 2nd argument to include the TOML file to write to.
# If using elf file, extract useful FW and Emulator information from elf file
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
    
	# TODO: Keep for editing later.
	# Print Relevant Unicorn Information extracted from ELF
    """
	print("Memory Map")
	print("   Start: " + hex(ExecVAddr))
	print("   Size:  " + hex(emu_mem_size))
	print("\nMemory Write Information")
	print("   .text Addr: " + hex(TextAddr))
	print("   .text Size: " + hex(TextSize))
	print("   .data Addr: " + hex(DataAddr))
	print("   .data Size: " + hex(DataSize))

	# NOTE: Can use the function after main() as the stopping address
	print("\nEmulator Begin and Until Addresses")
	print("   Begin: " + hex(MainAddr))
	print("   Until: " + hex(ExitAddr))

	print("\nGenerated Binary Files for Unicorn:")
	print("   " + TextBin)
	print("   " + DataBin)
    """
	
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

# Remove unwanted quotations around hexadecimal values.
def del_quotes(config):
	# Re-write config
	parsed_config = ""
	
	# Re-write line by line
	for line in config.splitlines():	
		# Don't re-write quotes.
		if ("reg" not in line):
			for ch in range(0, len(line)):
				if (line[ch] != "\""):
					parsed_config = parsed_config + line[ch]
					
			# Add newline.		
			parsed_config = parsed_config + "\n"
			
		# Re-write quotes ONLY if on same line as "reg."		
		else:
			parsed_config = parsed_config + line + "\n"
	
	return parsed_config



if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Setup emulator and configuration file')
	parser.add_argument('-g', '--gen-periph',
						help='Generate Peripheral Modules and Registers',
						metavar='TOML_File',
						dest='gen_periph')	
	
	parser.add_argument('-e', '--extract-elf',
						help='Extract FW and emulator info from elf',
						metavar='ELF_File',
						dest='extract_elf')
																	
	args = parser.parse_args();
	
	if args.gen_periph:
		generate_periph(args.gen_periph)
		
	elif args.extract_elf:
		extract_elf(args.extract_elf)
		

		
	
