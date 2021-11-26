/* Parse emulatorConfig.toml and extract values important for the emulator 
 *
 *
*/

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include "qemu/osdep.h"
#include "hw/core/cpu.h"
#include "exec/cpu-common.h"
#include "cpea/emulatorConfig.h"
#include "cpea/toml.h"
#include "hw/arm/cpea.h"

CpeaMMIO *MMIO[MAX_MMIO];
INST_handle *SR_INSTANCE[MAX_INST];

uint32_t minPeriphaddr = 0xffffffff;
uint32_t maxPeriphaddr = 0x0;

int mmio_total;
int SR_count;
int DR_count;

int inst_i=0;

// Read peripheral configurations and commit them to memory
CpeaMachineState *emuConfig(CpeaMachineState *config){
 	
 	/***********************************
		Parse Configuration File and Store configurations   
    ************************************/ 	  
    toml_table_t* mmio;		// mmio table from TOML file.    
	FILE *fp;				
	char errbuf[200];

	printf("***Configure Emulator***\n");	
	
	fp = fopen("../../emulatorConfig.toml", "r");	
    if (!fp)
        error("cannot open emulatorConfig.toml - ", strerror(errno), "", "");
 
    // Root table 
    toml_table_t* root_table = toml_parse_file(fp, errbuf, sizeof(errbuf));
    fclose(fp);
   	if (!root_table)
   		error("cannot parse emulatorConfig.toml - ", errbuf, "", "");
    
    // Gather and Store firmware and memory map info. Return 'mmio' and 'config' tables    	
    mmio = parseConfig(root_table, &config);
    
    /***********************************
		Peripheral Configurations   
    ************************************/
    
    // Gather and Store mmio information.
	mmioConfig(mmio);
       	     	    	            
    /*** Free Memory for config file ***/
    toml_free(root_table); 
      
    printf("   - Complete\n\n"); 
    
    return config;        
}

// Parse data from config.core and config.mem_map
toml_table_t* parseConfig(toml_table_t* root_table, CpeaMachineState **config){
	
	
    /*
    	Traverse to [config] table
    */
    
 	toml_table_t* config_tab = toml_table_in(root_table, "config");
 	if (!config_tab){
 		error("missing [config]", "", "", "");
 	}  	
 	    
 	/*
        Traverse to [config.options] table 	 	
 	*/
 	toml_table_t* opts_tab = toml_table_in(config_tab, "options");
 	if (!opts_tab){
 		error("missing [config.options]", "", "", "");
 	} 
 	
 	/*
 	    Check if core configs exist.
 	    Allowed values are checked in Python script, but should also be checked here.
 	*/
 	toml_table_t* core_tab = toml_table_in(config_tab, "core");
 	
 	// Handle core configs
 	// TODO: Check if core_tab or mem_map_tab if-blocks execute when core and mem_map don't exist in TOML
 	if (core_tab){

        // cpu model  
        toml_datum_t cpu_key = toml_string_in(core_tab, "cpu_model");
        if (!cpu_key.ok){
    	    error("Cannot read config.core.cpu_model. It should exist.", "", "", "");
        }

        // mpu
        toml_datum_t bitband_key = toml_int_in(core_tab, "bitband");
        if (!bitband_key.ok){
    	    error("Cannot read config.core.bitband. It should exist.", "", "", "");
        }
        
        // num_irq
        toml_datum_t irq_key = toml_int_in(core_tab, "num_irq");
        if (!irq_key.ok){
    	    error("Cannot read config.core.num_irq. It should exist.", "", "", "");
        }                                   
        
        // Update new core configs, replacing old defaults. 
        strcpy((*config)->cpu_model, cpu_key.u.s);       
        (*config)->has_bitband = bitband_key.u.i;
        (*config)->num_irq = irq_key.u.i;
      	
       	// Need to free string associated with toml_datum_t structure.
 	    free(cpu_key.u.s);  	    
 	}
 	

 	
 	/*
 	    Check if core mem_map exists
 	*/
    toml_table_t* mem_map_tab = toml_table_in(config_tab, "mem_map");
    
    // Handle mem_map configs
    if (mem_map_tab){

        // flash base
        toml_datum_t flash_base_key = toml_int_in(mem_map_tab, "flash_base");
        if (!flash_base_key.ok){
    	    error("Cannot read config.mem_map.flash_base. It should exist.", "", "", "");
        }
        
        // flash size
        toml_datum_t flash_size_key = toml_int_in(mem_map_tab, "flash_size");
        if (!flash_size_key.ok){
    	    error("Cannot read config.mem_map.flash_size. It should exist.", "", "", "");
        }        
        
        // sram base
        toml_datum_t sram_base_key = toml_int_in(mem_map_tab, "sram_base");
        if (!sram_base_key.ok){
    	    error("Cannot read config.mem_map.sram_base. It should exist.", "", "", "");
        }        
        
        // sram size
        toml_datum_t sram_size_key = toml_int_in(mem_map_tab, "sram_size");
        if (!sram_size_key.ok){
    	    error("Cannot read config.mem_map.sram_size. It should exist.", "", "", "");
        }        
        
        // sram base 2
        toml_datum_t sram_base2_key = toml_int_in(mem_map_tab, "sram_base2");
        if (!sram_base2_key.ok){
    	    error("Cannot read config.mem_map.sram_base2. It should exist.", "", "", "");
        }        
        
        // sram size 2
        toml_datum_t sram_size2_key = toml_int_in(mem_map_tab, "sram_size2");
        if (!sram_size2_key.ok){
    	    error("Cannot read config.mem_map.sram_size2. It should exist.", "", "", "");
        }        
        
        // sram base 3
        toml_datum_t sram_base3_key = toml_int_in(mem_map_tab, "sram_base3");
        if (!sram_base3_key.ok){
    	    error("Cannot read config.mem_map.sram_base3. It should exist.", "", "", "");
        }        
        
        // sram size 3
        toml_datum_t sram_size3_key = toml_int_in(mem_map_tab, "sram_size3");
        if (!sram_size3_key.ok){
    	    error("Cannot read config.mem_map.sram_size3. It should exist.", "", "", "");
        }        
        
        // Update new mem_map configs, replacing old defaults
        (*config)->flash_base = flash_base_key.u.i;
        (*config)->flash_size = flash_size_key.u.i;
        (*config)->sram_base = sram_base_key.u.i;
        (*config)->sram_size = sram_size_key.u.i;
        (*config)->sram_base2 = sram_base2_key.u.i;
        (*config)->sram_size2 = sram_size2_key.u.i;
        (*config)->sram_base3 = sram_base3_key.u.i;
        (*config)->sram_size3 = sram_size3_key.u.i;
            
    } 
    
    /*
        Traverse to mmio table
    */
 	toml_table_t* mmio = toml_table_in(root_table, "mmio");
 	if (!mmio){
 		error("missing [mmio]", "", "", "");
 	}
    
    return mmio;
    
}


// Parse MMIO configurations
int mmioConfig(toml_table_t* mmio){
	
	toml_table_t* periph;		// Ptr to peripheral table
	toml_table_t* table_ptr;	// Ptr to module tables. e.g. config, addr, reset, flags
	int struct_i=0;				// Index for allocating/accessing peripheral module structs
	int periph_i;				// Peripheral Index for peripheral tables and peripheral counts
	int mod_i;					// Peripheral Module Index
	int tab_i;					// Index to iterate through modules. e.g. config, addr, reset, flags
	int init_i;                 // Index to initialize MMIO struct.
	           
	char p_str[20];				// String of a peripheral
	int pid;					// Iterable Peripheral Index
	int p_total;				// Total number of possible peripherals
	
    // TODO: No longer maintaining list of acceptable peripherals in TOML. Need to 
    //       get rid of the list here as well. 
	const char periph_str[3][10] = {"uart", "gpio", "generic"};
	p_total = sizeof(periph_str)/sizeof(periph_str[0]);

    toml_table_t* mmio_count = toml_table_in(mmio, "count");
 	if (!mmio){
 		error("missing [mmio.count]", "", "", "");
 	}
 	
 	mmio_total=0;
 	// Index [mmio.count] and allocate memory for each peripheral. Init MMIO struct.
 	for (periph_i=0; ;periph_i++){
 	
 		// Get current peripheral & count. Leave if none.
 		const char* periph_count = toml_key_in(mmio_count, periph_i);
 		if (!periph_count)
 			break;
 			
 		// Get number of Peripheral modules
    	toml_datum_t num_mods = toml_int_in(mmio_count, periph_count);
    	if (!num_mods.ok){
    		error("Cannot read mmio.count.%s", periph_count, "", "");
    	}
    	
    	// Check for invalid module count
    	// TODO: Get an appropriate MAX_MMIO count. Also use another variable instead of the typecasted struct.union combo
    	if ((int)num_mods.u.i <= 0)
			continue;
		else if ((int)num_mods.u.i > MAX_MMIO - 1 ){
			printf("WARNING: MMIO count set to %d, but cannot exceed %d.\n", (int)num_mods.u.i, MAX_MMIO - 1);
			printf("Setting to 15.\n");	
			num_mods.u.i = 15;	
		}
    	
    	mmio_total = mmio_total + (int)num_mods.u.i;	// Get total number of peripheral modules for this periph
		
 		// Get peripheral ID for struct.
 		// FIXME: Currently have no use for this.
 		for (pid=0; pid<=p_total; pid++){
 			if (pid == p_total)
 				error("No peripheral match in mmio.count", "", "", "");

 			strcpy(p_str, periph_str[pid]);
			strcat(p_str, "_count");
			if (!strcmp(p_str, periph_count))
				break;
	
 		} 		
 		// Get current peripheral string name based on periphal ID above.
    	strcpy(p_str, periph_str[pid]);
    		
    	// Get current peripheral ptr
    	periph = toml_table_in(mmio, p_str);
 		if (!periph){
 			error("missing [mmio.]", p_str, "", "");
 		}
 		
 		// Allocate space for modules. Init MMIO metadata, addresses, resets, and flags		
 		for (mod_i=0; struct_i<mmio_total; struct_i++, mod_i++){
 		    // TODO: Can probably allocate this all in 1 go, rather than each loop cycle. 
    		MMIO[struct_i] = (CpeaMMIO *)malloc(sizeof(CpeaMMIO));
    		if (MMIO[struct_i] == NULL){
    			// TODO: Update message since module # is hard for a user to track
    			printf("Periph struct memory not allocated for module%d\n", struct_i);
    		}
    		
    		// Update MMIO metadata          
    		MMIO[struct_i]->periphID = pid;
    		MMIO[struct_i]->modID = mod_i;
    		MMIO[struct_i]->modCount = (int)num_mods.u.i;	
    		   		
    		// Initialize MMIO struct to 0s. 
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
			
			/*
			    Parse config, addr, reset, & flags tables
			*/  
    		const char* module_str = toml_key_in(periph, mod_i);
    		if (!module_str) 
    			break;
    		
    		toml_table_t* module_ptr = toml_table_in(periph, module_str);
    		if (!module_ptr)
    			// TODO: Change error message
 				error("Failed to get periph table from module %s", module_str, "", "");
 			
			// Loop config, addr, reset, & flags tables. Parse Each.
 			for (tab_i=0; ;tab_i++){
 		
 				const char* table_str = toml_key_in(module_ptr, tab_i);
 				if (!table_str)
 					break;
 		
 				table_ptr = toml_table_in(module_ptr, table_str);
 				if (!table_ptr)
 					error("Failed to get table from module %s", module_str, "", "");
 		 	
 		 		// Not on "flags" table
 		 		if (strcmp(table_str, "flags"))
					parseKeys(p_str, module_str, table_ptr, table_str, struct_i);
				
				// ON "flags" table	
				else
					setFlags(table_ptr, struct_i);
 			}			
 						
    	}
	
 	}
   			
   	return 0;	  		
}

void parseKeys(char* periph_str, const char* module_str, toml_table_t* table_ptr, const char* table_str, int mod_i){

 	int SR_i=0;				// Status Register Index
 	int DR_i=0;				// Data Register Index
 	int key_i=0;			// Key Index
 	int has_irq;            // Store if irq exists or not
 	int irqn;               // Store irqn
 	const char *has_irq_s;  // Store boolean string for irq
 	
 	const char* key_str;	// Store name of any key 	  
 	
 	toml_table_t* irq_ptr;	// ptr to irq inline table
 	toml_datum_t irq_true;  // irq enabled for peripheral
 	toml_datum_t irqn_key;  // Defines IRQn  
 	toml_datum_t key_data;	// Store data from any key
 	
 		
 	uint32_t base_addr;     // Need base address to check if user entered and offset or absolute address.
 	uint32_t data;			// Key Data to store.
 		
 	// Parse SR/DR counts & irq info 
 	if (!strcmp(table_str, "config")){
 		// Get SR_count string
		key_str = toml_key_in(table_ptr, 0);
		
		// Get SR_count number
		key_data = toml_int_in(table_ptr, key_str);
		if (!key_data.ok)
    		error("Cannot read key data", "", "", "");
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
    		error("Cannot read key data", "", "", "");
		data = (uint32_t)key_data.u.i;
		
		// FIXME: This should be between 1 and 3???
		// DR count must be between 0 and 17 
		if (data <= 0)
			DR_count = 1;			
		else if (data > 0 && data <= 16)
			DR_count = data;		
		else	
			DR_count = data;
			
		// Parse IRQ info
		key_str = toml_key_in(table_ptr, 2);
		if (!key_str){
            fprintf(stderr, "ERROR: Missing irq table in [mmio].[%s].[%s].[%s]\n", periph_str, module_str, table_str);
            exit(1);	
    	}	    	
    	irq_ptr = toml_table_in(table_ptr, key_str);
    	   	
    	// Default irq info   	
    	MMIO[mod_i]->irq_enabled = 0;
    	MMIO[mod_i]->irqn = 0xffff;
    	    
    	// Parse 'true' key 
    	irq_true = toml_int_in(irq_ptr, "enabled");    	    	
        // User didn't enter integer
    	if (!irq_true.ok){    	    
  	        irq_true = toml_string_in(irq_ptr, "enabled"); 	         
  	        if(!irq_true.ok){
  	            fprintf(stderr, "ERROR: Bad data for \"true\" in [mmio.%s.%s.%s.irq]\n", periph_str, module_str, table_str);
                exit(1);  
  	        }   	        
  	        has_irq_s = irq_true.u.s;
  	        if (!strcmp(has_irq_s, "false"))
  	            has_irq = 0;
  	        else if (!strcmp(has_irq_s, "true"))
  	            has_irq = 1;
  	        else{
  	            fprintf(stderr, "ERROR: Must use boolean for \"true\" in [mmio.%s.%s.%s.irq]\n", periph_str, module_str, table_str);
                exit(1);    	        
  	        }
  	        free(irq_true.u.s);       
    	}
    	
    	// User entered integer
    	else{
            has_irq = irq_true.u.i;
            if (has_irq < 0 || has_irq > 1){
  	            fprintf(stderr, "ERROR: Must use boolean for \"true\" in [mmio.%s.%s.%s.irq]\n", periph_str, module_str, table_str);
                exit(1);                 
            }
    	}
    
        // Parse 'irqn' key
        if (has_irq){
            irqn_key = toml_int_in(irq_ptr, "irqn");
            if (!irqn_key.ok){
        	    fprintf(stderr, "ERROR: [mmio.%s.%s.%s.irq] has an irq enabled, but no IRQn\n", periph_str, module_str, table_str);
                exit(1);           
            }                
            irqn = irqn_key.u.i;
            if (irqn < 0 || irqn > 480){
        	    fprintf(stderr, "ERROR: [mmio.%s.%s.%s.irq] must have irqn in range [0, 480]\n", periph_str, module_str, table_str);
                exit(1);              
            }
            
            // Update irq info for this module
            MMIO[mod_i]->irq_enabled = 1;
            MMIO[mod_i]->irqn = irqn;
        }    	
			
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
    			error("Cannot read key data", "", "", "");
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

				// Store addr data. SRs are looped first.	
				if (SR_i < SR_count){
					MMIO[mod_i]->SR_ADDR[SR_i] = data;
					/*
					    0) Make a hash table that holds data of type 'MMIOkey'
					    1) Compute Hash for the addr (data)
					       - Can do bitwise
					    2) Add struct to hash table based on computed index.
					       - Making sure there is no collision.
					    Have
					    1) AddrKey: data
					    2) MMIOIndex: mod_i
					    3) regType: SR
					    4) regIndex: SR_i
					*/ 
					SR_i++;	
				}
				else{
					MMIO[mod_i]->DR_ADDR[DR_i] = data;
					// 
					DR_i++;
				} 
				
				
 
				// Keep track of lowest and highest addr.
				if (data < minPeriphaddr){
					minPeriphaddr = data;
					// Max addr can't be less than Min addr
				    if (maxPeriphaddr == 0)
					    maxPeriphaddr = data;	
				}	    				
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
    			error("Cannot read key data", "", "", "");
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
 		
 	 	
 	else if (!strcmp(table_str, "flags"))
 		;
 	else
    	error("Trying to access a module table that doesn't exist.", "", "", "");  	
 	
 
 	// Get address range for this module
 	MMIO[mod_i]->minAddr = minPeriphaddr;
 	MMIO[mod_i]->maxAddr = maxPeriphaddr;
 	
}

int setFlags(toml_table_t* flag_tab, int mod_i){
	int flag_i;					// SR Flag Index
	int SR_i;					// String Index for Status Registers
	int flag_bit;				// Bit location that flag belongs to
	int flag_val;               // Value of SR bit user chose (optional)
	uint32_t flag_addr;         // Address location of SR access (optional)
	const char* flag_name;		// Name of current flag
	const char* flag_reg;		// Name of register flag belongs to
	//const uint8_t* bytes;       // ptr to SR value for 8 bit r/w
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
 			error("Failed to get Flag table: %s", flag_name, "", "");
 			
 		// Get the register the flag belongs to 
    	reg_str = toml_string_in(flag_ptr, "reg");
    	if (!reg_str.ok)
    		error("Failed to get flag register from: %s", flag_name, "", "");
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
    		error("Failed to get flag bit location from: %s", flag_name, "", "");	
    	flag_bit = flag_int.u.i;
    	
    	if (flag_bit < 0 || flag_bit > 31){
    	    printf("SR bit value must be between 0-31. You put %d at %s", flag_bit, flag_name);
    	    exit(1);
    	}
    	
    	// Get the flag value (must be 1 or 0)		
		flag_int = toml_int_in(flag_ptr, "val");
    	if (!flag_int.ok)
    		error("Failed to get flag value from: ", flag_name, "", "");	
    	flag_val = flag_int.u.i;
    	   	
    	if (flag_val != 0 && flag_val != 1){
    	    printf("SR flag value must be '0' or '1'. You put %d at %s.", flag_val, flag_name);
    	    exit(1);
    	}    	 	
   	    
    	// Find correct index to store SR to
    	for (SR_i=0; SR_i<8; SR_i++){	
    		if (!strcmp(flag_reg, reg_name[up_case][SR_i]) || !strcmp(flag_reg, reg_name[low_case][SR_i])){
    		   
    		   	// Check if user wants to save a SR instance. 
		        flag_int = toml_int_in(flag_ptr, "addr");
		        
		        // Instance doesn't exist. Update SR now.
    	        if (!flag_int.ok){
                    addr_str = toml_string_in(flag_ptr, "addr");
                    if(!addr_str.ok)
                        error("Failed to get addr value from: ", flag_name, "", ""); 
                    else{
                        
     			        // Set/Clear SR bit. 
    			        if (flag_val == 1)				
    			            SET_BIT(MMIO[mod_i]->SR[SR_i], flag_bit);
    			    
    			        // Explicitly clear incase reset value is '1' for this bit.    
    			        else
    			            CLEAR_BIT(MMIO[mod_i]->SR[SR_i], flag_bit);    

				        
				        // Free for TOML. 
				        free(addr_str.u.s);                      
                    }                    
    	        }
    	
    	        // Instance exists. Save it for later. 
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
    	            SR_INSTANCE[inst_i]->INST_ADDR = flag_addr;
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
    				error("Please give \"reg\" name in formats SR(1-8) or sr(1-8). You gave: ", flag_reg, "", "");
    			}
    		}	
    	}

	}	

	return 0;

}

void error(const char *msg, const char *msg1, const char *msg2, const char *msg3)
{
	fprintf(stderr, "ERROR: %s%s%s%s\n", msg, msg1?msg1:"", msg2?msg2:"", msg3?msg3:"");
	exit(1);
}
