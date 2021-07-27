/* Parse emulatorConfig.toml and extract values important for the emulator 
 *
 *
*/

#include <unicorn/unicorn.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "emulatorConfig.h"
#include "toml.h"

// Read config file, parse emulator configurations, and configure emulator
void emuConfig(uc_engine *uc, char *arm_code, int code_size){
 	
 	/***********************************
		Parse Configuration File and Store configurations   
    ************************************/ 	  
    toml_table_t* mmio;		// mmio table from TOML file.    
	FILE *fp;				
	char errbuf[200];

	printf("***Configure Emulator***\n");	
	
	fp = fopen("emulatorConfig.toml", "r");	
    if (!fp)
        error("cannot open emulatorConfig.toml - ", strerror(errno));
 
    // Root table 
    toml_table_t* root_table = toml_parse_file(fp, errbuf, sizeof(errbuf));
    fclose(fp);
   	if (!root_table)
   		error("cannot parse emulatorConfig.toml - ", errbuf);
    
    // Gather and Store firmware and memory map info    	
    mmio = parseTOML(root_table);
    
    /***********************************
		General Emulator Configurations.   
    ************************************/
     
    // Memory Map for Emulator
    map_memory(uc);
    
    // Initialize flash memory with firmware (code and data)
    flash_init(uc, arm_code, code_size);
    
    // Init ARM Registers (includes SP, LR)
    // TODO: See if there is a more legitimate way to init SP.
    // TODO: Check if LR needs init. I think not. 
    reg_init(uc);
    
    /***********************************
		Peripheral Configurations   
    ************************************/
    
    // Gather and Store mmio information.
	mmioConfig(uc, mmio);
       	     	    	            
    /*** Free Memory for config file ***/
    toml_free(root_table); 
      
    printf("   - Complete\n\n");         
}

// Gather and Store configurations from TOML.
toml_table_t* parseTOML(toml_table_t* root_table){
	
    /*
    	Traverse to [mem_map] table
    */
 	toml_table_t* mem_map = toml_table_in(root_table, "mem_map");
 	if (!mem_map){
 		error("missing [mem_map]", "");
 	} 
 	
    /*
    	TODO: May keep these incase user wants to optionally enter their memory map in.
    	Extract values from memory map
    */
    
    /*
    // code addresses
    toml_datum_t code_addr = toml_int_in(mem_map, "code_addr");
    if (!code_addr.ok){
    	error("Cannot read mem_map.code_addr", "");
    }
    CODE_ADDR = (uint32_t)code_addr.u.i;   // Get integer from union  
    
    // code size
    toml_datum_t code_size = toml_int_in(mem_map, "code_size");
    if (!code_size.ok){
    	error("Cannot read mem_map.code_size", "");
    }
    CODE_SIZE = (uint32_t)code_size.u.i;     
    
    // SRAM addr
    toml_datum_t sram_addr = toml_int_in(mem_map, "sram_addr");
    if (!sram_addr.ok){
    	error("Cannot read mem_map.sram_addr", "");
    }
    SRAM_ADDR = (uint32_t)sram_addr.u.i;   
    
    // SRAM size
    toml_datum_t sram_size = toml_int_in(mem_map, "sram_size");
    if (!sram_size.ok){
    	error("Cannot read mem_map.sram_size", "");
    }
    SRAM_SIZE = (uint32_t)sram_size.u.i;    
    */
    
    /*
    	Done reading general memory map information
    	Store ptr to [mmio] table for peripheral configurations
    */
    
	// mmio == mem_map.mmio
	// NOTE: This is used in individual peripheral config functions.
 	toml_table_t* mmio = toml_table_in(root_table, "mmio");
 	if (!mmio){
 		error("missing [mem_map.mmio]", "");
 	}
       
    /*
    	Done reading mmio information
    	Traverse to [firmware] table
    */
    
	
 	toml_table_t* firmware = toml_table_in(root_table, "firmware");
 	if (!firmware){
 		error("missing [firmware]", "");
 	} 
 	  
 	// Traverse to [firmware.code]
 	toml_table_t* code = toml_table_in(firmware, "code");
 	if (!code){
 		error("missing [firmware.code]", "");
 	}  
 	 
 	// code address
    toml_datum_t code_addr = toml_int_in(code, "code_addr");
    if (!code_addr.ok){
    	error("Cannot read code.code_addr", "");
    }
    CODE_ADDR = (uint32_t)code_addr.u.i; 
 	
    // NOTE: code size currently determined by file size at the moment
    /*
    toml_datum_t code_size = toml_int_in(code, "code_size");
    if (!code_size.ok){
    	error("Cannot read code.code_size", "");
    }
    CODE_SIZE = (uint32_t)code_size.u.i; 
    */ 
    	
 	// Traverse to [firmware.data]
 	toml_table_t* data = toml_table_in(firmware, "data");
 	if (!code){
 		error("missing [firmware.data]", "");
 	}      	
    	
 	// data address
    toml_datum_t data_addr = toml_int_in(data, "data_addr");
    if (!data_addr.ok){
    	error("Cannot read data.data_addr", "");
    }
    DATA_ADDR = (uint32_t)data_addr.u.i; 
 	
    // NOTE: data size currently determined by file size at the moment
    /*
    toml_datum_t data_size = toml_int_in(data, "data_size");
    if (!data_size.ok){
    	error("Cannot read data.data_size", "");
    }
    DATA_SIZE = (uint32_t)data_size.u.i; 
    */     	
    
 	// Traverse to [firmware.execution]
 	toml_table_t* execution = toml_table_in(firmware, "execution");
 	if (!execution){
 		error("missing [firmware.execution]", "");
 	}        	
    	
 	// entry point
 	/*
 	TODO: See if we need this for ELF files not specific to an MCU. 
 	      Currently, reading Reset Handler from Vector Table. 
    toml_datum_t entry = toml_int_in(execution, "entry");
    if (!entry.ok){
    	error("Cannot read execution.entry", "");
    }
    START = (uint32_t)entry.u.i; 
    */
    
    
    //TODO: See if we need this for ELF files. We would need for ending at particular points. 
 	// end of execution
    toml_datum_t end = toml_int_in(execution, "end");
    if (!end.ok){
    	error("Cannot read execution.end", "");
    }
    END = (uint32_t)end.u.i;
    
    return mmio;
    
}

// FIXME: Want to use smaller ranges if we can .. but then user needs to manually enter ranges unless we could automate somehow. 
// TODO: Check if we can make ADDR and SIZE for FLASH/SRAM hardcoded to the ARM Cortex-M specification
void map_memory(uc_engine *uc){

    // TODO: Need to make a different variable to signify where firmware will start. It may not always start at 0x0,
    //       but maybe at 0x0800 0000 for example. Keep CODE_ADDR for mem map, but need a FW start variable for where fw
    //       exists virtually.
	// CODE region for Cortex-M
	CODE_ADDR = 0;
	CODE_SIZE = 0x20000000;
	
	// SRAM region for Cortex-M
	SRAM_ADDR = 0x20000000;	
	SRAM_SIZE = 0x20000000;  

	// MMIO region for Cortex-M
	MMIO_ADDR = 0x40000000;
	MMIO_SIZE = 0x20000000;

    // External Ram region for Cortex-M
    EXT_RAM_ADDR = 0x60000000;
    EXT_RAM_SIZE = 0x40000000;
    
    // External Device region for Cortex-M
    EXT_DEV_ADDR = 0xA0000000;
    EXT_DEV_SIZE = 0x40000000;
    
    // Private Peripheral Bus region for Cortex-M
    PRIV_BUS_ADDR = 0xE0000000;
    PRIV_BUS_SIZE = 0x00100000;
    
    // Vendor-Specific memory region for Cortex-M
    VENDOR_MEM_ADDR = 0xE0100000;
    VENDOR_MEM_SIZE = 0x1ff00000; // 0x1ff00000

	// Map Code region
	if (uc_mem_map(uc, CODE_ADDR, CODE_SIZE, UC_PROT_ALL)){
		printf("Failed to map code region to memory. Quit\n");
		exit(1);
	}
	
	// Map SRAM region 
	if (uc_mem_map(uc, SRAM_ADDR, SRAM_SIZE, UC_PROT_ALL)){
		printf("Failed to map sram region to memory. Quit\n");
		exit(1);	
	}	
		
	// Map MMIO region
	if (uc_mem_map(uc, MMIO_ADDR, MMIO_SIZE, UC_PROT_READ | UC_PROT_WRITE )){
		printf("Failed to map MMIO region to memory. Quit\n");
		exit(1);
	}
	
	// Map External RAM region
	if (uc_mem_map(uc, EXT_RAM_ADDR, EXT_RAM_SIZE, UC_PROT_ALL)){
		printf("Failed to map external ram region to memory. Quit\n");
		exit(1);
	}
	
	// Map External Device region
	if (uc_mem_map(uc, EXT_DEV_ADDR, EXT_DEV_SIZE, UC_PROT_READ | UC_PROT_WRITE)){
		printf("Failed to map external device region to memory. Quit\n");
		exit(1);
	}	
	
	// Map Private Peripheral bus
	if (uc_mem_map(uc, PRIV_BUS_ADDR, PRIV_BUS_SIZE, UC_PROT_READ | UC_PROT_WRITE)){
		printf("Failed to map private peripheral bus region to memory. Quit\n");
		exit(1);
	}	
	
	// Map Vendor-specific memory
	if (uc_mem_map(uc, VENDOR_MEM_ADDR, VENDOR_MEM_SIZE, UC_PROT_READ | UC_PROT_WRITE)){
		printf("Failed to map vendor-specific region to memory. Quit\n");
		exit(1);
	}		
	
}

 
// Initialize flash memory (code and data)
void flash_init(uc_engine *uc, char *arm_code, int code_size){
	
	// Write fw code to flash!	
	if (uc_mem_write(uc, CODE_ADDR, arm_code, code_size)){ 
		printf("Failed to write code to memory. Quit\n");
		exit(1);
	}
	free(arm_code);
	arm_code = NULL;
	
}


// Initialize all ARM Core Registers. 
void reg_init(uc_engine *uc){

	// Read SP and Reset Handler (PC) from Vector Table
	
	// Read SP from address 0x0000 0000
	uc_mem_read(uc, 0, &SP, 4);
	
	// Read Reset Handler (PC) from address 0x0000 0004
	uc_mem_read(uc, 4, &START, 4);

	// TODO: Find what they are reset to upon reset
	/* ARM Core Registers */	
	r_r0 = 0x0000;     	// r0
	r_r1 = 0x0001;     	// r1
	r_r2 = 0x0002;     	// r2 
	r_r3 = 0x0003;     	// r3
	r_r4 = 0x0004;     	// r4
	r_r5 = 0x0005;     	// r5
	r_r6 = 0x0006;     	// r6
	r_r7 = 0x0007;     	// r7 
	r_r8 = 0x0008;     	// r8
	r_r9 = 0x0009;     	// r9
	r_r10 = 0x000A;    	// r10

	FP = SP;	        // r11  // TODO: Would FW do this assignment for us?
	r_r12 = 0x000C;    	// r12
	SP = SP;      		// r13
	LR = 0xffffffff;	// r14	Reset Value // TODO: See if this needs set. I think not.  
 
}

// Configure MMIO emulation.
int mmioConfig(uc_engine *uc, toml_table_t* mmio){
	
	toml_table_t* periph;		// Ptr to peripheral table
	toml_table_t* table_ptr;	// Ptr to module tables. e.g. config, addr, reset, flags
	uint32_t data;				// Store key data
	int struct_i;				// Index for allocating/accessing peripheral module structs
	int key_i;					// Key index for any table TODO: We need this?
	int periph_i;				// Peripheral Index for peripheral tables and peripheral counts
	int mod_i;					// Peripheral Module Index
	int tab_i;					// Index to iterate through modules. e.g. config, addr, reset, flags
	int SR_i;					// Status Register Index - Keeps track of which SR we are storing to.
	int DR_i;					// Data Register Index - Keeps track of which DR we are storing to.
	int init_i;                 // Index to initialize MMIO struct.
	
	char p_str[20];				// String of a peripheral
	int pid;					// Iterable Peripheral Index
	int p_total;				// Total number of possible peripherals
	

	const char periph_str[3][10] = {"uart", "gpio", "generic"};
	p_total = sizeof(periph_str)/sizeof(periph_str[0]);

	mod_count = 0;		
    inst_i = 0;
	
	// Init MMIO callback range.
	minMMIOaddr = 0x40000000;
	maxMMIOaddr = 0x5fffffff;
	
	// Will keep track of min/max reg addr for modules.
	minPeriphaddr = 0xffffffff;
	maxPeriphaddr = 0x0;					
 		   
    toml_table_t* mmio_count = toml_table_in(mmio, "count");
 	if (!mmio){
 		error("missing [mmio.count]", "");
 	}
 	 
 	// Index Peripheral Counts/Modules and allocate memory for each peripheral. Init MMIO struct
 	struct_i=0;
 	for (periph_i=0; ;periph_i++){
 	
 		// Get current peripheral & count. Leave if none.
 		const char* periph_count = toml_key_in(mmio_count, periph_i);
 		if (!periph_count)
 			break;
 			
 		// Get number of Peripheral modules
    	toml_datum_t num_mods = toml_int_in(mmio_count, periph_count);
    	if (!num_mods.ok){
    		error("Cannot read mmio.count.%s", periph_count);
    	}
    	
    	// Check for invalid module count
    	// TODO: Get an appropriate MAX_MMIO count. Also use another variable instead of the typecasted struct.union combo
    	if ((int)num_mods.u.i <= 0)
			continue;
		else if ((int)num_mods.u.i > MAX_MMIO - 1 ){
			printf("WARNING: MMIO count set to %d, but cannot exceed %d. ", (int)num_mods.u.i, MAX_MMIO - 1);
			printf("Setting to 15.");	
			num_mods.u.i = 15;	
		}
    	
    	mod_count = mod_count + (int)num_mods.u.i;	// Get total number of peripheral modules for this periph

 		
 		// Get peripheral ID for struct.
 		for (pid=0; pid<=p_total; pid++){
 			if (pid == p_total)
 				error("No peripheral match in mmio.count", "");

 			strcpy(p_str, periph_str[pid]);
			strcat(p_str, "_count");
			if (!strcmp(p_str, periph_count))
				break;
	
 		}
 		
 		 // Get current peripheral string name
    	strcpy(p_str, periph_str[pid]);
    		
    	// Get current peripheral ptr
    	periph = toml_table_in(mmio, p_str);
 		if (!periph){
 			error("missing [mmio.]", p_str);
 		}
 		
 		// Allocate space for modules. Init MMIO metadata, addresses, resets, and flags
 		for (mod_i=0; struct_i<mod_count; struct_i++, mod_i++){
    		MMIO[struct_i] = (MMIO_handle *)malloc(sizeof(MMIO_handle));
    		if (MMIO[struct_i] == NULL){
    			// TODO: Update message
    			printf("Periph struct memory not allocated for module%d\n", struct_i);
    		}	
    		
    		//printf("periph: %s\n", periph_count);
    		
    		// Add metadata to MMIO struct 
    		MMIO[struct_i]->periphID = pid;
    		//printf("pid: %d\n", MMIO[struct_i]->periphID);
    		MMIO[struct_i]->modID = mod_i;
    		//printf("mod: %d\n", MMIO[struct_i]->modID);
    		MMIO[struct_i]->modCount = (int)num_mods.u.i;
    		//printf("modCount: %d\n", MMIO[struct_i]->modCount);  	
    		   		
    		// Initialize MMIO struct
    		for (init_i=0; init_i<20; init_i++){
    		    if (init_i < 2){
    		        MMIO[struct_i]->DR_ADDR[init_i] = 0;
    		        MMIO[struct_i]->DR_RESET[init_i] = 0;
    		        MMIO[struct_i]->DR[init_i] = 0;      
    		    }
    		        
    		    MMIO[struct_i]->SR_ADDR[init_i] = 0;
    		    MMIO[struct_i]->SR_RESET[init_i] = 0;
    		    MMIO[struct_i]->SR[init_i] = 0;   		    
    		}    		
    		MMIO[struct_i]->SR_INST = 0;

    		
			/* Add config, addr, reset, flags to MMIO struct */
			
 			// Get current module string   
    		const char* module_str = toml_key_in(periph, mod_i);
    		if (!module_str) 
    			break;
    		
    		// Get current module ptr
    		toml_table_t* module_ptr = toml_table_in(periph, module_str);
    		if (!module_ptr)
    			// TODO: Change error message
 				error("Failed to get periph table from module %s", module_str);
 			
			// Loop config, addr, reset, & flags table. Parse Each.
 			for (tab_i=0; ;tab_i++){
 		
 				// Get table string. 
 				const char* table_str = toml_key_in(module_ptr, tab_i);
 				if (!table_str)
 					break;
 		
 				// Get table ptr 
 				table_ptr = toml_table_in(module_ptr, table_str);
 				if (!table_ptr)
 					error("Failed to get table from module %s", module_str);
 		 	
 		 		// Not on "flags" table
 		 		if (strcmp(table_str, "flags"))
					parseKeys(p_str, module_str, table_ptr, table_str, struct_i);
				
				// ON "flags" table	
				else
					setFlags(uc, table_ptr, struct_i);
 			}			
 						
    	}
	
 	}

   	// SANITY CHECK. Check if the min and max addresses for UART match.
   	//printf("minUARTaddr: 0x%x\nmaxUARTaddr: 0x%x\n", minUARTaddr, maxUARTaddr);
   	
		
   	return 0;	  		
}

void parseKeys(char* periph_str, const char* module_str, toml_table_t* table_ptr, const char* table_str, int mod_i){

 	int SR_i=0;				// Status Register Index
 	int DR_i=0;				// Data Register Index
 	int key_i=0;			// Key Index
 	
 	const char* key_str;	// Store name of any key
 	toml_datum_t key_data;	// Store data from any key
 		
 	uint32_t base_addr;     // Need base address to check if user entered and offset or absolute address.
 	uint32_t data;			// Key Data to store.
 	
 	// Get SR and DR counts. 
 	if (!strcmp(table_str, "config")){
 		// Get SR_count string
		key_str = toml_key_in(table_ptr, 0);
		
		// Get SR_count number
		key_data = toml_int_in(table_ptr, key_str);
		if (!key_data.ok)
    		error("Cannot read key data", "");
		data = key_data.u.i;
		
		// SR count must be between 0 and 17 
		if (data <= 0)
			SR_count = 1;
		else if (data > 0 && data <= 16)
			SR_count = data;		
		else
			SR_count = 16;
		
		// Get DR_count string
		key_str = toml_key_in(table_ptr, 1);
		
		// Get DR_count number
		key_data = toml_int_in(table_ptr, key_str);
		if (!key_data.ok)
    		error("Cannot read key data", "");
		data = (uint32_t)key_data.u.i;
		
		// DR count must be between 0 and 17 
		if (data <= 0)
			DR_count = 1;			
		else if (data > 0 && data <= 16)
			DR_count = data;		
		else	
			DR_count = data;
	}	
		
	// Get the register addresses	
 	else if(!strcmp(table_str, "addr")){
 		// Index the addr keys
 		for (key_i=0; ; key_i++){
 		
 			// Get addr key string
 			key_str = toml_key_in(table_ptr, key_i);
 			if (!key_str)
 				break;
 				
  			// Get data from the current key
    		toml_datum_t key_data = toml_int_in(table_ptr, key_str);
    		if (!key_data.ok)
    			error("Cannot read key data", "");
    		data = (uint32_t)key_data.u.i;			
 			
 			// Skip Storing data if 0xFFFF
    		if (data == 0xFFFF){
    			if (SR_i < SR_count)
    				SR_i++;
    			else
    				DR_i++;  				
    			continue;
    		}

 			// Get base addr
			if (key_i == 0){
    			base_addr = data;
    			if (base_addr < 0x40000000 || base_addr > 0x5fffffff){
    				fprintf(stderr, "ERROR: Base Address for %s%s out of bounds. [0x40000000 - 0x5fffffff]\n", periph_str, module_str);
					exit(1);	
    			}				
    			MMIO[mod_i]->BASE_ADDR = base_addr;				 
    		}
    		
    		else{
    		 						
				// Check if user entered offset and convert to absolute address.
				if (data < base_addr)
					data = data + base_addr;

				// Store addr data	
				if (SR_i < SR_count){
					MMIO[mod_i]->SR_ADDR[SR_i] = data;
					SR_i++;	
				}
				else{
					MMIO[mod_i]->DR_ADDR[DR_i] = data;
					DR_i++;
				} 
				
 
				// Keep track of lowest and highest addr.
				if (data < minPeriphaddr)
					minPeriphaddr = data;
					if (maxPeriphaddr == 0)
					    maxPeriphaddr = data;					
				else if (data > maxPeriphaddr)
					maxPeriphaddr = data;					
	
			}
				
 		}
 		
 	}
 	
 	// Get the register resets	
 	else if(!strcmp(table_str, "reset")){
 		// Index the reset keys
 		for (key_i=0; ; key_i++){
 		
 			// Get reset key string
 			key_str = toml_key_in(table_ptr, key_i);
 			if (!key_str)
 				break;
 				
  			// Get data from the current key
    		toml_datum_t key_data = toml_int_in(table_ptr, key_str);
    		if (!key_data.ok)
    			error("Cannot read key data", "");
    		data = (uint32_t)key_data.u.i;			
 			
 			// Skip Storing data if 0xFFFF
    		if (data == 0xFFFF){
    			if (SR_i < SR_count)
    				SR_i++;
    			else
    				DR_i++;  				
    			continue;
    		}

			// Store reset data	
			if (SR_i < SR_count){
				MMIO[mod_i]->SR_RESET[SR_i] = data;
				SR_i++;	
			}
			else{
				MMIO[mod_i]->DR_RESET[DR_i] = data;
				DR_i++;
			} 
			
 		}
 		
 	}
 		
 	// 	
 	else if (!strcmp(table_str, "flags"))
 		;
 	else
    	error("Trying to access a module table that doesn't exist.");  	
 	
 
 	// Get address range for this module
 	MMIO[mod_i]->minAddr = minPeriphaddr;
 	MMIO[mod_i]->maxAddr = maxPeriphaddr;
 	
}

int setFlags(uc_engine *uc, toml_table_t* flag_tab, int mod_i){
	int flag_i;					// SR Flag Index
	int SR_i;					// String Index for Status Registers
	int flag_bit;				// Bit location that flag belongs to
	int flag_val;               // Value of SR bit user chose (optional)
	uint32_t flag_addr;         // Address location of SR access (optional)
	const char* flag_name;		// Name of current flag
	const char* flag_reg;		// Name of register flag belongs to
	toml_table_t* flag_ptr;		// ptr to flag table
	toml_datum_t reg_str;		// Holds register string from flag table
	toml_datum_t flag_int;		// Holds an int value from flag table
	toml_datum_t addr_str;      // Holds "optional" string from address value.
	
	// Access upper/lower case SR string
	enum letter_case {up_case, low_case};
	
	// TODO: Only doing up to 8 str for now. Find better number in future	
	char reg_name[2][8][4] = {
	{{"SR1"},{"SR2"},{"SR3"},{"SR4"},{"SR5"},{"SR6"},{"SR7"},{"SR8"}},
	{{"sr1"},{"sr2"},{"sr3"},{"sr4"},{"sr5"},{"sr6"},{"sr7"},{"sr8"}}
	};
	
	// Loop the "flags" table for current peripheral
	for (flag_i = 0; ; flag_i++){
 		// Check if table exists and leave when we finish.    
    	flag_name = toml_key_in(flag_tab, flag_i);
    	if (!flag_name) 
    		break;
			
		// Get the current Flag table ptr from its name
    	flag_ptr = toml_table_in(flag_tab, flag_name);
    	if (!flag_ptr)
 			error("Failed to get Flag table: %s", flag_name);
 			
 		// Get the register the flag belongs to 
    	reg_str = toml_string_in(flag_ptr, "reg");
    	if (!reg_str.ok)
    		error("Failed to get flag register from: %s", flag_name);
    	flag_reg = reg_str.u.s;
        		
		// Skip flag and exit.    		 
    	if (!strcmp(flag_reg, "reg")){
            // Need to free string associated with toml_datum_t structure.
			free(reg_str.u.s);
    		continue;
    	}	
   		
 		// Get the bit location the flag belongs to	(must be 0 - 31)	
		flag_int = toml_int_in(flag_ptr, "bit");
    	if (!flag_int.ok)
    		error("Failed to get flag bit location from: %s", flag_name);	
    	flag_bit = flag_int.u.i;
    	
    	if (flag_bit < 0 || flag_bit > 31){
    	    printf("SR bit value must be between 0-31. You put %d at %s", flag_bit, flag_name);
    	    exit(1);
    	}
    	
    	// Get the flag value (must be 1 or 0)		
		flag_int = toml_int_in(flag_ptr, "val");
    	if (!flag_int.ok)
    		error("Failed to get flag value from: ", flag_name);	
    	flag_val = flag_int.u.i;
    	   	
    	if (flag_val != 0 && flag_val != 1){
    	    printf("SR flag value must be '0' or '1'. You put %d at %s.", flag_val, flag_name);
    	    exit(1);
    	}    	 	
   	    
    	// Loop through list of possible reg names and check for matches in flag table.   	
    	for (SR_i=0; SR_i<8; SR_i++){	
    		if (!strcmp(flag_reg, reg_name[up_case][SR_i]) || !strcmp(flag_reg, reg_name[low_case][SR_i])){
    		   
    		   	// Check if user wants to save a SR instance, if not then just commit to memory. 
		        flag_int = toml_int_in(flag_ptr, "addr");
		        
		        // Instance doesn't exist. Commit SR to memory. 
    	        if (!flag_int.ok){
                    addr_str = toml_string_in(flag_ptr, "addr");
                    if(!addr_str.ok)
                        error("Failed to get addr value from: ", flag_name); 
                    else{
                        
     			        // Set/Clear SR bit and commit to memory. 
    			        if (flag_val == 1)				
    			            SET_BIT(MMIO[mod_i]->SR[SR_i], flag_bit);
    			    
    			        // Explicitly clear incase reset value is '1' for this bit.    
    			        else
    			            CLEAR_BIT(MMIO[mod_i]->SR[SR_i], flag_bit);    
    			    				
    			        if (uc_mem_write(uc, MMIO[mod_i]->SR_ADDR[SR_i], &MMIO[mod_i]->SR[SR_i], 4)){
					        printf("Failed to set bit for SR at module %d. Quit\n", mod_i);
					        exit(1);
				        } 
				        
				        // Free for TOML. 
				        free(addr_str.u.s);                      
                    }                    
    	        }
    	
    	        // Instance exists, so save it for later. 
    	        else{
    	            // Allocate space for SR instance.
    	            SR_INSTANCE[inst_i] = (INST_handle *)malloc(sizeof(INST_handle));
    		        if (SR_INSTANCE[inst_i] == NULL){
    		            // TODO: update message to say which periph&module.
    			        printf("Failed to allocate SR instance for %s", flag_name);
    			        exit(1);
    		        }
    		        
    		        // There is a SR instance for this module. 
    		        MMIO[mod_i]->SR_INST = 1;
    		        
    		        // Save SR instance		
    	            flag_addr = flag_int.u.i;
    	            SR_INSTANCE[inst_i]->PROG_ADDR = flag_addr;
    	            SR_INSTANCE[inst_i]->BIT = flag_bit;
    	            SR_INSTANCE[inst_i]->VAL = flag_val;
    	                	            
    	            // Get ready for next allocation.
    	            inst_i++;       	     
    	        }
    		   		
                free(reg_str.u.s);
				break;   	  						
    		}
    		
    		// Incorrect register naming format	
    		else{  		
    			if (SR_i == 7){
    			    free(reg_str.u.s);
    				error("Please give \"reg\" name in formats SR(1-8) or sr(1-8). You gave: ", flag_reg, "");
    			}
    		}	
    	}

	}	

	return 0;

}


void error(const char *msg, const char* msg1, const char* msg2)
{
	fprintf(stderr, "ERROR: %s%s%s\n", msg, msg1?msg1:"", msg2?msg2:"");
	exit(1);
}
