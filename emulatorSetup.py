"""
Things to add:
	- Argument parsing when running script.
		1) Elf File 
		2) Verbose Mode to print results
	
	- See if we ever need to calculate .text or .data size here since emulator currently handles that.
	
	- *** IMPORTANT *** Update exit addr to end of main, or find another suitable last instruction
"""

import subprocess
from tomlkit import parse
from tomlkit import dumps
from tomlkit import integer  
from tomlkit import comment
from elftools.elf.elffile import ELFFile

# Get emulator and firmware configuration details
elf = "SimpleUart.elf"

with open(elf, 'rb') as f:
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
		header = section.header	
		
		# Get .text section info (.text == 33)
		if header['sh_name'] == 33:
			TextAddr = header['sh_addr']
			TextSize = header['sh_size']
		
		# Get .data section info (.data == 98)
		elif header['sh_name'] == 98:
			DataAddr = header['sh_addr']
			DataSize = header['sh_size']
		
		
		
"""
# Get Executables Virtual Address
proc1 = subprocess.run(['readelf', '-l', elf],
						stdout=subprocess.PIPE,	# Pipe to stdout object
						text=True)	   			# Use text and not binary		   
					   					   				
proc2 = subprocess.run(['grep', 'LOAD'],
						input=proc1.stdout,		# Get output from prev stdout
						stdout=subprocess.PIPE,
						text=True)

proc3 = subprocess.run(['grep', 'R E'],
						input=proc2.stdout,
						stdout=subprocess.PIPE,
						text=True)
					
proc4 = subprocess.run(['awk', '{print $3;}'],
						input=proc3.stdout,
						stdout=subprocess.PIPE,
						text=True)	
ExecVAddr = int(proc4.stdout, 16)


# Get Data Virtual Address
proc1 = subprocess.run(['readelf', '-l', elf],
					   stdout=subprocess.PIPE,	# Pipe to stdout object
					   text=True)	   			# Use text and not binary		   
					   					   				
proc2 = subprocess.run(['grep', 'LOAD'],
						input=proc1.stdout,		# Get output from prev stdout
						stdout=subprocess.PIPE,
						text=True)

proc3 = subprocess.run(['grep', 'RW'],
						input=proc2.stdout,
						stdout=subprocess.PIPE,
						text=True)
					
proc4 = subprocess.run(['awk', '{print $3;}'],
						input=proc3.stdout,
						stdout=subprocess.PIPE,
						text=True)	
DataVAddr = int(proc4.stdout, 16)

# Get Data Section Size
proc1 = subprocess.run(['readelf', '-l', elf],
					   stdout=subprocess.PIPE,	# Pipe to stdout object
					   text=True)	   			# Use text and not binary		   
					   					   				
proc2 = subprocess.run(['grep', 'LOAD'],
						input=proc1.stdout,		# Get output from prev stdout
						stdout=subprocess.PIPE,
						text=True)

proc3 = subprocess.run(['grep', 'RW'],
						input=proc2.stdout,
						stdout=subprocess.PIPE,
						text=True)
					
proc4 = subprocess.run(['awk', '{print $6;}'],
						input=proc3.stdout,
						stdout=subprocess.PIPE,
						text=True)				
DataSize = int(proc4.stdout, 16)
														
# Calculate Total Memory Size for emulator
fw_mem_size = ExecVAddr + DataVAddr + DataSize	# Total Size
align = 4096 - (fw_mem_size%4096)				# Align to 4096 for unicorn
emu_mem_size = fw_mem_size + align				# Total Emulator Memory

# Get .text Address
proc1 = subprocess.run(['readelf', '-S', elf],
					   stdout=subprocess.PIPE,	# Pipe to stdout object
					   text=True)	   			# Use text and not binary		   
					   					   				
proc2 = subprocess.run(['grep', '-w', '.text'],
						input=proc1.stdout,		# Get output from prev stdout
						stdout=subprocess.PIPE,
						text=True)

proc3 = subprocess.run(['cut', '-c', '42-49'],
						input=proc2.stdout,
						stdout=subprocess.PIPE,
						text=True)
TextAddrHex = "0x" + proc3.stdout
TextAddr = int(TextAddrHex, 16)

# Get .text Size
proc1 = subprocess.run(['readelf', '-S', elf],
					   stdout=subprocess.PIPE,	# Pipe to stdout object
					   text=True)	   			# Use text and not binary		   
					   					   				
proc2 = subprocess.run(['grep', '-w', '.text'],
						input=proc1.stdout,		# Get output from prev stdout
						stdout=subprocess.PIPE,
						text=True)

proc3 = subprocess.run(['cut', '-c', '58-63'],
						input=proc2.stdout,
						stdout=subprocess.PIPE,
						text=True)
TextSizeHex = "0x" + proc3.stdout
TextSize = int(TextSizeHex, 16)

# Get .data Address
proc1 = subprocess.run(['readelf', '-S', elf],
					   stdout=subprocess.PIPE,	# Pipe to stdout object
					   text=True)	   			# Use text and not binary		   
					   					   				
proc2 = subprocess.run(['grep', '-w', '.data'],
						input=proc1.stdout,		# Get output from prev stdout
						stdout=subprocess.PIPE,
						text=True)

proc3 = subprocess.run(['cut', '-c', '42-49'],
						input=proc2.stdout,
						stdout=subprocess.PIPE,
						text=True)
DataAddrHex = "0x" + proc3.stdout
DataAddr = int(DataAddrHex, 16)

# Get .data Size
proc1 = subprocess.run(['readelf', '-S', elf],
					   stdout=subprocess.PIPE,	# Pipe to stdout object
					   text=True)	   			# Use text and not binary		   
					   					   				
proc2 = subprocess.run(['grep', '-w', '.data'],
						input=proc1.stdout,		# Get output from prev stdout
						stdout=subprocess.PIPE,
						text=True)

proc3 = subprocess.run(['cut', '-c', '58-63'],
						input=proc2.stdout,
						stdout=subprocess.PIPE,
						text=True)
DataSizeHex = "0x" + proc3.stdout
DataSize = int(DataSizeHex, 16)

# Get Main Addr
proc1 = subprocess.run(['nm', elf],
					   stdout=subprocess.PIPE,	# Pipe to stdout object
					   text=True)	   			# Use text and not binary		   
					   					   				
proc2 = subprocess.run(['grep', '-w', 'main'],
						input=proc1.stdout,		# Get output from prev stdout
						stdout=subprocess.PIPE,
						text=True)

proc3 = subprocess.run(['awk', '{print $1}'],
						input=proc2.stdout,
						stdout=subprocess.PIPE,
						text=True)
MainAddrHex = "0x" + proc3.stdout
MainAddr = int(MainAddrHex, 16)

# Get End Addr
proc1 = subprocess.run(['readelf', '-s', elf],
					   stdout=subprocess.PIPE,	# Pipe to stdout object
					   text=True)	   			# Use text and not binary		   
					   					   				
proc2 = subprocess.run(['grep', 'FUNC'],
						input=proc1.stdout,		# Get output from prev stdout
						stdout=subprocess.PIPE,
						text=True)

proc3 = subprocess.run(['grep', '-w', '_exit'],
						input=proc2.stdout,
						stdout=subprocess.PIPE,
						text=True)
					
proc4 = subprocess.run(['awk', '{print $2}'],
						input=proc3.stdout,
						stdout=subprocess.PIPE,
						text=True)
ExitAddrHex = "0x" + proc4.stdout
ExitAddr = int(ExitAddrHex, 16)
"""
						
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
"""
print("Emulator Begin and Until Addresses")
print("   Begin: " + MainAddrHex, end='')
print("   Until: " + ExitAddrHex)
"""
print("\nGenerated Binary Files for Unicorn:")
print("   " + TextBin)
print("   " + DataBin)


"""
# Update toml dictionary with ELF data

# Load entire TOML as a dictionary
config = parse(open('emulatorConfig.toml').read())

# Update flash addr
config['mem_map']['flash_addr'] = ExecVAddr
config['mem_map']['flash_addr'].comment(hex(ExecVAddr) + ", Generated by emulatorSetup.py")

# Update flash size
config['mem_map']['flash_size'] = emu_mem_size
config['mem_map']['flash_size'].comment(hex(emu_mem_size) + ", Generated by emulatorSetup.py")

# Update .text start
config['firmware']['code']['code_addr'] = TextAddr
config['firmware']['code']['code_addr'].comment(hex(TextAddr) + ", Generated by emulatorSetup.py")

# .text size determine by emulator at the moment.
#config['firmware']['code']['code_size'] = TextSize
#config['firmware']['code']['code_size'].comment(TextSizeHex + ", Generated by emulatorSetup.py")

# Update .data start
config['firmware']['data']['data_addr'] = DataAddr
config['firmware']['data']['data_addr'].comment(hex(DataAddr) + ", Generated by emulatorSetup.py")

# .data size determine by emulator at the moment.
#config['firmware']['data']['data_size'] = DataSize
#config['firmware']['data']['data_size'].comment(DataSizeHex + ", Generated by emulatorSetup.py")

# Update entry point
config['firmware']['execution']['entry'] = MainAddr
config['firmware']['execution']['entry'].comment(hex(MainAddr) + ", Generated by emulatorSetup.py")

# Update exit point (NOT updating since this hasn't been tested to work)
#config['firmware']['execution']['end'] = ExitAddr
#config['firmware']['execution']['end'].comment(hex(ExitAddr) + ", Generated by emulatorSetup.py")
"""

"""
# Write new configurations to a test TOML file

# Dumps the .toml file as a string while preserving formatting
string = dumps(config)
#print(string)
#with open('testConfig.toml', 'w') as f:
#	f.write(string)
"""




