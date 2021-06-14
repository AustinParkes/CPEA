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
# TODO: Fix this madness. (May just import *)
from tomlkit import parse
from tomlkit import dumps
from tomlkit import integer  
from tomlkit import comment
from tomlkit import table
from tomlkit import inline_table
from tomlkit import nl
from elftools.elf.elffile import ELFFile
from elftools.elf.elffile import SymbolTableSection

"""
	TODO:
	1) Generate a recursive table [mmio.uart.0.config]
	   - Can quote an then remove quotes (Not preferred)
	   - API support?
	   
	2) Indentations
	   - indent() method apart of 'Table' class and likely other classes
	   
	3) Get inline tables   
"""
def generate_periph(config_file):
	
	p_flags = {'uart': {'f1': "TX_data_empty", 'f2': "RX_data_full", 'f3': "TX_Complete",
						'f4': "RX_enable_ack", 'f5': "TX_enable_ack"},
			   'gpio': {'f1': "Generic_Flag1", 'f2': "Generic_Flag2", 'f3': "Generic_Flag3"}}
		
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
						break
					
								
					# Don't overwrite existing modules
					if num_exist == 0:
						config['mmio'][peri] = table()
						config['mmio'][peri].indent(4)
					
					# Generate as many modules as 'count' specifies
					for i in range(num_exist, count):
						generate_module(config, peri, p_flags, i)
					
					# FIXME: This won't execute unless modules are added.
					# Read peripheral configurations	
					for i in range(count):
						mod_i = str(i)
						SR_count = config['mmio'][peri][mod_i]['config']['SR_count']
						print(SR_count)
						
		
	#print(config)
	#print(dumps(config))
	
	# Write to TOML
	config = dumps(config)
	with open('testConfig.toml', 'w') as f:
		f.write(config)

def generate_module(config, peri, p_flags, i):
	mod_i = str(i)
	# Generate config table
	config['mmio'][peri].update({mod_i: {'config': {'SR_count': 2, 'DR_count': 2}}})
	# TODO: Move the indentations to the end of this.
						
	config['mmio'][peri][mod_i].indent(4)
	config['mmio'][peri][mod_i]['config'].indent(4)					
					
	# Generate addr table
	config['mmio'][peri][mod_i].update({'addr': {'base_addr': 0, 'SR1_addr': 0, 
													'SR2_addr': 0, 'DR1_addr': 0, 'DR2_addr': 0}})
					
	config['mmio'][peri][mod_i]['addr'].indent(4)					
									
	# Generate reset table
	config['mmio'][peri][mod_i].update({'reset': {'SR1_reset': 0, 'SR2_reset': 0, 
													'DR1_reset': 0, 'DR2_reset': 0}})
					
	config['mmio'][peri][mod_i]['reset'].indent(4)						
					
	# Generate flag table											   
	config['mmio'][peri][mod_i].update({'flags': {}})
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
			
			
# TODO: Add 2nd argument to include the TOML file to write to.
# If using elf file, extract useful FW and Emulator information from elf file
def extract_elf(elf):
	# Get emulator and firmware configuration details
	#elf = "SimpleUart.elf"
	
	with open(elf, 'rb') as f:
	
		
		# Check if elf file was given
		f.seek(0)
		if f.read(4) != b"\x7fELF":
			f.seek(0)
			print("File given is not an ELF file.")
			return
		
		f.seek(0)
		elffile = ELFFile(f)		
		# Get Segment Headers for memory map. Headers stored as dictionaries.
		for segment in elffile.iter_segments():	
			header = segment.header				# Get the header dictionary
			if header['p_type'] == 'PT_LOAD':
		
				# Get Exectuable Virtual Address
				if header['p_flags'] == 5:		# R E (Executable Header)
					ExecVAddr = header['p_vaddr']
				
				# Get Data Virtual Address and Size	
				elif header['p_flags'] == 6:	# RW  (Data Header)
					DataVAddr = header['p_vaddr']
					DataSize = header['p_memsz']

			
		# Calculate Total Memory Size for emulator
		fw_mem_size = ExecVAddr + DataVAddr + DataSize	# Total Size
		align = 4096 - (fw_mem_size%4096)				# Align to 4096 for unicorn
		emu_mem_size = fw_mem_size + align				# Total Emulator Memory
	
		# Get Section Headers for code and data (.text and .data). Headers stored as dictionaries.
		for section in elffile.iter_sections():
	
			# Get entry and exit points
			if isinstance(section, SymbolTableSection):
				for symbol in section.iter_symbols():
					if symbol.name == 'main':
						func_addr = symbol.entry['st_value']
						MainAddr = func_addr

					elif symbol.name == 'exit':
						func_addr = symbol.entry['st_value']
						ExitAddr = func_addr
				
			header = section.header	
			# Get .text section info (.text == 33)
			if header['sh_name'] == 33:
				TextAddr = header['sh_addr']
				TextSize = header['sh_size']
		
			# Get .data section info (.data == 98)
			elif header['sh_name'] == 98:
				DataAddr = header['sh_addr']
				DataSize = header['sh_size']
			

						
	# Generate .text and .data binary files for Unicorn
	elf_name = elf.split('.')				# Remove ".elf" extension from elf file
	TextBin = elf_name[0] + ".code.bin"
	DataBin = elf_name[0] + ".data.bin"

	# .text binary
	out = subprocess.run(['arm-none-eabi-objcopy', '-O', 'binary', '-j', '.text', elf, TextBin],
					   stderr=subprocess.PIPE,	# Pipe to stdout object
					   text=True)	   			# Use text and not binary
	if (out.stdout):
		print("objcopy error: Couldn't produce .text binary")
	
	# .data binary					   								
	out = subprocess.run(['arm-none-eabi-objcopy', '-O', 'binary', '-j', '.data', elf, DataBin],
					   stderr=subprocess.PIPE,	# Pipe to stdout object
					   text=True)	   			# Use text and not binary
	if (out.stdout):
		print("objcopy error: Couldn't produce .data binary")



	# Print Relevant Unicorn Information extracted from ELF
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


	# Update toml dictionary with ELF data

	# Load entire TOML as a dictionary
	config = parse(open('testConfig.toml').read())

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
	parsed_config = ""

	# Get rid of all quotations from the TOML file by re-writing a new block of string without them.
	for i in range(0, len(config)):
		if (config[i] != "\"") and (i < stop_index):
			parsed_config = parsed_config + config[i]

	# Concatenate the remaining, uneditted string
	parsed_config = parsed_config + config[stop_index:]
	#print(parsed_config)

	with open('testConfig.toml', 'w') as f:
		f.write(parsed_config)


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
		

		
	
