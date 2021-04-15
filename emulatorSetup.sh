#!/bin/bash

# Try 'cut'

# Check if argument is NULL 
if [ -z "$1" ]
  then
    echo "Please supply an ELF file"
    exit 1
fi

# Check if argument is ELF file
# $? store return value. Anything non-zero is error
ELFCheck=$(readelf -h $1 2>&1)   # (2>&1) redirects output as stderr instead of stdout
if [ "$?" -ne 0 ]
  then
    echo "Argument is not an ELF file"
    exit 1
fi

### ADD THIS CHECK LATER: Check if ELF is Executable    

# Argument has passed all tests
ELF="$1"

##### ELF Variables #####
# Executable Code Virtual Address
ExecVAddr=$(readelf -l $ELF | grep 'LOAD' | grep 'R E'| awk '{print $3;}')
# Executable code Memory size
ExecMSize=$(readelf -l $ELF | grep 'LOAD' | grep 'R E'| awk '{print $6;}')
# Data Section Virtual Address
DataVAddr=$(readelf -l $ELF | grep 'LOAD' | grep 'RW'| awk '{print $3;}')
# Data section Memory Size
DataMSize=$(readelf -l $ELF | grep 'LOAD' | grep 'RW'| awk '{print $6;}')
# Entry Point
Entry=$(readelf -h $ELF | grep 'Entry' | awk '{print $4;}')
# Main()
Main="0x$(nm SimplePollUart.elf | grep -w main | awk '{print $1}')"
# End (Emulator stops at this address)
Exit="0x$(readelf -s $ELF | grep 'FUNC' | grep -w '_exit' | awk '{print $2}')"


#.text Virtual Address and Size
TextAddr="0x$(readelf -S SimplePollUart.elf | grep -w '.text' | cut -c 42-49)"
TextSize="0x$(readelf -S SimplePollUart.elf | grep -w '.text' | cut -c 58-63)"

#.Data Virtual Address and Size
DataAddr="0x$(readelf -S SimplePollUart.elf | grep -w '.data' | cut -c 42-49)"
DataSize="0x$(readelf -S SimplePollUart.elf | grep -w '.data' | cut -c 58-63)"


##### Unicorn Variables ####

# Calculate memory map for code and data
fw_mem_sz=$((ExecVAddr+DataVAddr+DataMSize))
align_rem=$((4096-(fw_mem_sz%4096)))
emu_mem_sz=$(printf '0x%08x' $((fw_mem_sz+align_rem)))


##### Make Firmware for Unicorn #####
# Template for the binaries we will make
fname=${ELF%.*}   # Gets rid of the .elf extension
# File names for Text and Data binaries
TextBin="$fname.code.bin"
DataBin="$fname.data.bin"


# Generate binary for .text section
arm-none-eabi-objcopy -O binary -j .text $ELF $TextBin
# Generate binary for .data section
arm-none-eabi-objcopy -O binary -j .data $ELF $DataBin

##### List all the information Gathered #####
echo -e "ELF Information:"

# List addresses that we will write firmware code/data to
echo "Program Sections"
echo "  Exectuable Section"

echo "    VirtAddr:	$ExecVAddr"

echo  "    MemSiz:	$ExecMSize"

echo "  Data Section"
echo "    VirtAddr:	$DataVAddr"

echo "    MemSiz:	$DataMSize"


echo -e "\n  Main and _exit addresses"
#echo "    Entry:	$Entry"
echo "    Main:	$Main"

echo -n "    End:	$Exit"

# Perform Unicorn memory map and memory write calculations
# with above elf information
echo -e "\n\nUnicorn Information:"


# Combination of Executable and Data Section
echo "  Memory Map"
echo "    Start:	$ExecVAddr"
echo "    Size:	$emu_mem_sz"

echo -e "\n  Memory Write Information"
echo "    .text Addr:	$TextAddr"
echo "    .text Size:	$TextSize"

echo -e "\n    .data Addr:	$DataAddr"
echo "    .data Size:	$DataSize"

echo -e "\n  Emulator Begin and Until addresses"
echo "    Begin:	$Main"
echo "    Until:	$Exit"

echo -e "\nGenerated Binary Files for Unicorn:"
echo	"  $TextBin"
echo	"  $DataBin"
