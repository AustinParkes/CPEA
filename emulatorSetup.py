"""
Things to add:
	- Argument parsing when running script.
		1) Elf File 
		2) Verbose Mode to print results
	- Adding results to .toml file
	
	- Using Python Elf Parsing library instead?
	
	- Generate a backup of the configuration before writing	
	
	- See if we ever need to calculate .text or .data size here since emulator currently handles that.
	
	- Update exit addr to end of main, Or make the exit addr work.
"""

import subprocess
from tomlkit import parse
from tomlkit import dumps
from tomlkit import integer  
from tomlkit import comment

# Get emulator and firmware configuration details
elf = "SimpleUart.elf"

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


print("Memory Map")
print("   Start: " + hex(ExecVAddr))
print("   Size:  " + hex(emu_mem_size))
print("\nMemory Write Information")
print("   .text Addr: " + TextAddrHex, end='')   # No newline
print("   .text Size: " + TextSizeHex, end='')
print("   .data Addr: " + DataAddrHex, end='')
print("   .data Size: " + DataSizeHex)
print("Emulator Begin and Until Addresses")
print("   Begin: " + MainAddrHex, end='')
print("   Until: " + ExitAddrHex)
print("Generated Binary Files for Unicorn:")
print("   " + TextBin)
print("   " + DataBin)



# Place emulator/firmware Data into configuration File

#Load entire .toml as a dictionary
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

# Dumps the .toml file as a string while preserving formatting
string = dumps(config)

#print(string)

#with open('testConfig.toml', 'w') as f:
#	f.write(string)
	




