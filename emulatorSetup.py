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

print("Start: " + hex(ExecVAddr))
print("Size:  " + hex(emu_mem_size))


"""
ps = subprocess.run(['ps', '-A'], stdout=subprocess.PIPE)
processNames = subprocess.run(['grep', 'CMD'],
                              input=ps.stdout, stdout=subprocess.PIPE)
print(processNames.stdout)
"""
# Load entire .toml as a dictionary
#config = parse(open('testConfig.toml').read())

#print(config)

#print(config['table1']['key1'])

#config['table1']['key1'] = 0x20
#config['table1']['key1'].comment(hex(0x20))

# Dumps the .toml file as a string while preserving formatting
#string = dumps(config)

#print(string)
