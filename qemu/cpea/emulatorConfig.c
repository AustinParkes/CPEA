/* 
 * Parse emulatorConfig.toml and store MMIO/firmware user configurations for QEMU. 
 * Created by Austin Parkes
 * 
 * TODO: 1) Use Calloc instead of Malloc so everything in structs is init to 0 automatically
 *
 * TODO: 2) Force user to enter SR in all caps for 'flags' table. Keeps naming conventions consistent.
 *
 * TODO: 3) Need to revisit error/warning messages and improve the information they provide. Should also probably just use fprintf(stderr, ...)
 *          and ditch the fancy error() function. If line numbers can be provided with TOML API, that would also be an improvement on the error system.
 *           
 * TODO: 4) Need to provide better boundary conditions for much of the error checking. For example, we are arbitrarily using 100 as the max number of MMIOs.
            Just a matter of re-visiting all the boundary checks. Some of them are incorrect too and could lead to bugs manifesting. 
 *
 *
 * TODO: 6) Currently require a user to choose a peripheral that belongs in peripheral table. Figure out a better way to do this.
 *          Does the emulator really need to be aware of what 'UART' is? or 'GPIO'? It may just need to be aware of more specific things
 *          like how interrupts are handled with serial data like UART.  
 *
 * TODO: 7) XXX: I think I fixed this: 'mod_i' and 'struct_i' are used interchangeably which is confusing. They are technically different. Want to change this naming.
 *          Keeping for now because some of the code these names depend on could change anyway.
 *          Modules represent subsets of a peripheral: uart0, uart1, etc.
 *          Structures represent the peripherals as a whole: uart
 *
 * TODO: 8) Need a way to give a toml file as an argument to use it in place of the hardcoded "emulatorConfig.toml"                            
*/

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include "qemu/osdep.h"
#include "hw/arm/cpea.h"


CpeaMMIO *MMIO[MAX_MMIO];
INST_handle *SR_INSTANCE[MAX_INST];

uint32_t minPeriphaddr = 0xffffffff;
uint32_t maxPeriphaddr = 0x0;

int IRQtotal=0;
int mmio_total=0; 
int CR_count;       
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
      
    printf("***Complete***\n\n"); 
    
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
	//int init_i;               // Index to initialize MMIO struct.	           
	char p_name[20];			// Peripheral Name
	int pid;					// Peripheral ID
	int p_total;				// Total number of peripherals
	
    //"null", 
	const char valid_id[3][10] = {"generic", "uart", "gpio"};
	p_total = sizeof(valid_id)/sizeof(valid_id[0]);

    toml_table_t* mmio_count = toml_table_in(mmio, "count");
 	if (!mmio){
 		error("missing [mmio.count]", "", "", "");
 	}
 	
 	// Index [mmio.count] and allocate memory for each peripheral. Init MMIO struct.
 	for (periph_i=0; ;periph_i++){
 	
 		// Get current peripheral name. Leave if none.
 		const char* periph_count = toml_key_in(mmio_count, periph_i);
 		if (!periph_count)
 			break;
 		
 		// Reset peripheral name to re-use it.
 		memset(p_name, '\0', strlen(p_name));
 		
        // Chop off "_count" and we have our peripheral's name
 		strncpy(p_name, periph_count, strlen(periph_count) - 6);

 		// Get number of Peripheral modules
    	toml_datum_t num_mods = toml_int_in(mmio_count, periph_count);
    	if (!num_mods.ok){
    		error("Cannot read mmio.count.%s", periph_count, "", "");
    	}
    	
    	// Check for invalid module count
    	// TODO: Get an appropriate MAX_MODS count. Also use another variable instead of the typecasted struct.union combo
    	if ((int)num_mods.u.i <= 0)
			continue;
		else if ((int)num_mods.u.i > MAX_MODS - 1 ){
			printf("WARNING: MMIO count set to %d, but cannot exceed %d.\n", (int)num_mods.u.i, MAX_MMIO - 1);
			printf("Setting to 15.\n");	
			num_mods.u.i = 15;	
		}
    	
    	mmio_total = mmio_total + (int)num_mods.u.i;	// Get total number of peripheral modules for this periph
		
 		// Get peripheral ID, if it exists. 
 		/* TODO: Want a better way to give peripheral IDs. Currently,
 		         user needs to name their peripheral so it matches a name
 		         in our peripheral list. 
 		         
 		         Turn into function as well, so there is description of this
 		         in API.		
 		*/
 		for (pid=1; pid<=p_total; pid++){
 		
 		    // No match so no PID
 			if (pid == p_total){
 				pid = 0;
 				break;				
            }
            		
			// Peripheral Match. Will use PID later.
			if (!strcmp(p_name, valid_id[pid])){		
				break;
	        }
 		} 		
 		
    	// Get current peripheral ptr
    	periph = toml_table_in(mmio, p_name);
 		if (!periph){
 			error("missing [mmio.]", p_name, "", "");
 		}
 		
 		// Allocate space for modules. Init MMIO metadata, addresses, resets, and flags		
 		for (mod_i=0; struct_i<mmio_total; struct_i++, mod_i++){
 		
    		MMIO[struct_i] = (CpeaMMIO *)calloc(1, sizeof(CpeaMMIO));
    		if (!MMIO[struct_i]){
    			// TODO: Update message since module # is hard for a user to track
    			printf("Periph struct memory not allocated for module%d\n", struct_i);
    		}
    		
    		// Update MMIO metadata          
    		MMIO[struct_i]->periphID = pid;
    		MMIO[struct_i]->modID = mod_i;
    		MMIO[struct_i]->modCount = (int)num_mods.u.i;	
    		   		
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
					parseKeys(mmio, p_name, module_str, table_ptr, table_str, struct_i);
				
				// ON "flags" table	
				else
					setFlags(table_ptr, struct_i);		
 			}			
 						
    	}
	
 	}
		
   	return 0;	  		
}


void parseKeys(toml_table_t* mmio, char* p_name, const char* module_str, 
               toml_table_t* table_ptr, const char* table_str, int struct_i)
{

    int CR_i=0;             // Control Register Index
    int SR_i=0;				// Status Register Index
    int DR_i=0;				// Data Register Index
    int key_i=0;			// Key Index
    
    char reg_type[4];       // Helps determine register type   	
    const char* key_str;	// Store name of any key 	  
 	
    toml_datum_t key_data;	// Store data from any key
 			
    uint32_t base_addr;     // Need base address to check if user entered and offset or absolute address.
    uint32_t data;			// Key Data to store.
 	
 	// Hardware Configuration functions
 	void (*MMIOhwConfig[2])(toml_table_t*, char*, const char*, 
 	                          toml_table_t*, const char*, int) = {
 	    genericHWConfig,
 	    uartHWConfig    
 	}; 	
 	
 	// Interrupt Configuration Functions
 	void (*MMIOIntrConfig[2])(toml_table_t*, char*, const char*, 
 	                          toml_table_t*, const char*, int) = {
 	    genericIntrConfig,
 	    uartIntrConfig    
 	};
 	
 	// Interface Configuration Functions
 	void (*MMIOInterface[2])(toml_table_t*, char*, const char*, 
 	                          toml_table_t*, const char*, int) = {
 	    genericInterface,
 	    uartInterface    
 	}; 	
 	
    // Parse CR/SR/DR counts & irq info 
    if (!strcmp(table_str, "config")){
        
        // Get CR_count string
        key_str = toml_key_in(table_ptr, 0);
 
 	    // Get CR_count number
		key_data = toml_int_in(table_ptr, key_str);
		if (!key_data.ok)
    		error("Cannot read CR_count number", "", "", "");
		data = (uint32_t)key_data.u.i;
		
		// CR count must be between 0 and 20 
		if (data <= 0)
			CR_count = 0;
		else if (data > 0 && data <= 20)
			CR_count = data;		
		else
			CR_count = 20;		 	    
 	    
 		// Get SR_count string
		key_str = toml_key_in(table_ptr, 1);
		
		// Get SR_count number
		key_data = toml_int_in(table_ptr, key_str);
		if (!key_data.ok)
    		error("Cannot read SR_count number", "", "", "");
		data = (uint32_t)key_data.u.i;
		
		// SR count must be between 0 and 20 
		if (data <= 0)
			SR_count = 0;
		else if (data > 0 && data <= 20)
			SR_count = data;		
		else
			SR_count = 20;		
		
		// Get DR_count string
		key_str = toml_key_in(table_ptr, 2);
		
		// Get DR_count number
		key_data = toml_int_in(table_ptr, key_str);
		if (!key_data.ok)
    		error("Cannot read DR_count number", "", "", "");
		data = (uint32_t)key_data.u.i;
		
		// DR count must be between 0 and 3 
		if (data <= 0)
			DR_count = 0;			
		else if (data > 0 && data <= 2)
			DR_count = data;		
		else	
			DR_count = 2;
		
		
		/* Skip parsing flag count (table_ptr, 3) Don't need it here. */	
			
	}	
	
	// Get the register addresses	
 	else if(!strcmp(table_str, "addr")){
	    
 		// Index the addr keys
 		for (key_i=0; ; key_i++){
 		
 			// Get addr key string
 			key_str = toml_key_in(table_ptr, key_i);
 			if (!key_str)
 				break;
 			
 			// Get register type CR, SR, or DR
 			strncpy(reg_type, key_str, 2);
 			
  			// Get data from the current key
    		toml_datum_t key_data = toml_int_in(table_ptr, key_str);
    		if (!key_data.ok)
    			error("Cannot read key data", "", "", "");
    		data = (uint32_t)key_data.u.i;			
            
 			// Get base addr
			if (key_i == 0){
    			base_addr = data;			
    			MMIO[struct_i]->BASE_ADDR = base_addr;				 
    		}
    		
    		else{
    		 						
				// Check if user entered offset and convert to absolute address.
				if (data < base_addr)
					data = data + base_addr;

				// Store addr data for correct register
				if (!strcmp(reg_type, "CR")){
				    MMIO[struct_i]->CR_ADDR[CR_i] = data;
				    CR_i++;
				}	
				else if (!strcmp(reg_type, "SR")){
					MMIO[struct_i]->SR_ADDR[SR_i] = data;									
					SR_i++;	
				}
				else if (!strcmp(reg_type, "DR")){
					MMIO[struct_i]->DR_ADDR[DR_i] = data;
					DR_i++;
				} 

				// Keep track of lowest and highest addr for this peripheral
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
 		// Compute addr range for this peripheral 		
 		MMIO[struct_i]->mmioSize = maxPeriphaddr - minPeriphaddr;
 	}
 	
 	// Get the register resets	
 	else if(!strcmp(table_str, "reset")){
 		// Index the reset keys
 		for (key_i=0; ; key_i++){
 		
 			// Get key from reset table (string)
 			key_str = toml_key_in(table_ptr, key_i);
 			if (!key_str)
 				break;
 				 				
 			// Get register type (CR, SR, or DR)
 			strncpy(reg_type, key_str, 2);	
 			
  			// Get data from the current key
    		toml_datum_t key_data = toml_int_in(table_ptr, key_str);
    		if (!key_data.ok)
    			error("Cannot read key data", "", "", "");
    		data = (uint32_t)key_data.u.i;			

            if (!strcmp(reg_type, "CR")){
				MMIO[struct_i]->CR[CR_i] = data;
				CR_i++;	            
            }
			// Store reset data	
			else if (!strcmp(reg_type, "SR")){
				MMIO[struct_i]->SR[SR_i] = data;
				SR_i++;	
			}
			else if (!strcmp(reg_type, "DR")){
				MMIO[struct_i]->DR[DR_i] = data;
				DR_i++;
			} 
			
 		}
 		
 	}		
 	
 	else if (!strcmp(table_str, "hardware")){
 	    MMIOhwConfig[MMIO[struct_i]->periphID](mmio, p_name, module_str,
 	                                        table_ptr, table_str, struct_i);
 	}
 	
 	else if (!strcmp(table_str, "interrupts")){
 	    MMIOIntrConfig[MMIO[struct_i]->periphID](mmio, p_name, module_str,
 	                                        table_ptr, table_str, struct_i);
                                         	     	                                             	    
 	} 
 	
 	else if (!strcmp(table_str, "interface")){
 	    MMIOInterface[MMIO[struct_i]->periphID](mmio, p_name, module_str,
 	                                        table_ptr, table_str, struct_i);
 	}
 	
 	// flags table is handled in setFlags() 	
 	else if (!strcmp(table_str, "flags"))
 		;
 		
 	else{
        fprintf(stderr, "ERROR: Module table shouldn't exist: [%s.%s.%s]\n", 
            p_name, module_str, table_str);
        exit(1);  
 	}
 
 	// Get address range for this module
 	MMIO[struct_i]->minAddr = minPeriphaddr;
 	MMIO[struct_i]->maxAddr = maxPeriphaddr;
 	
}

int setFlags(toml_table_t* flag_tab, int struct_i){
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
	
	// TODO: Only allowing up to 32 str for now. Find better number in future	
	char reg_name[2][32][5] = {
	{{"SR1"},{"SR2"},{"SR3"},{"SR4"},{"SR5"},{"SR6"},{"SR7"},{"SR8"},
	 {"SR9"},{"SR10"},{"SR11"},{"SR12"},{"SR13"},{"SR14"},{"SR15"},{"SR16"},
	 {"SR17"},{"SR19"},{"SR19"},{"SR20"},{"SR21"},{"SR22"},{"SR23"},{"SR24"},
	 {"SR25"},{"SR26"},{"SR27"},{"SR28"},{"SR29"},{"SR30"},{"SR31"},{"SR32"}},
	 	 
	{{"sr1"},{"sr2"},{"sr3"},{"sr4"},{"sr5"},{"sr6"},{"sr7"},{"sr8"},
	 {"sr9"},{"sr10"},{"sr11"},{"sr12"},{"sr13"},{"sr14"},{"sr15"},{"sr16"},
	 {"sr17"},{"sr18"},{"sr19"},{"sr20"},{"sr21"},{"sr22"},{"sr23"},{"sr24"},
	 {"sr25"},{"sr26"},{"sr27"},{"sr28"},{"sr29"},{"sr30"},{"sr31"},{"sr32"}}	 
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
        		
		// Skip flag and go to start of loop    		 
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
    	for (SR_i=0; SR_i<32; SR_i++){	
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
    			            SET_BIT(MMIO[struct_i]->SR[SR_i], flag_bit);
    			    
    			        // Explicitly clear incase reset value is '1' for this bit.    
    			        else
    			            CLEAR_BIT(MMIO[struct_i]->SR[SR_i], flag_bit);    

				        
				        // Free for TOML. 
				        free(addr_str.u.s);                      
                    }                    
    	        }
    	
    	        // Instance exists. Save it for later. 
    	        else{
    	        
    	            // Allocate space for SR instance.
    	            SR_INSTANCE[inst_i] = (INST_handle *)calloc(1, sizeof(INST_handle));
    		        if (SR_INSTANCE[inst_i] == NULL){
    		            // TODO: update message to say which periph&module.
    			        printf("Failed to allocate SR instance for %s", flag_name);
    			        exit(1);
    		        }
    		        
    		        // There is a SR instance for this module. 
    		        MMIO[struct_i]->SR_INST = 1;
    		        
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
    			if (SR_i == 32-1){
    				error("Please give \"reg\" name in formats SR[1-32] or sr[1-32]. You gave: ", flag_reg, "", "");
    				free(reg_str.u.s);
    			}
    		}	
    	}

	}	
	return 0;

}

// Filler. Does nothing right now.
void genericHWConfig(toml_table_t* mmio, char* p_name, const char* module_str, 
            toml_table_t* table_ptr, const char* table_str, int struct_i)
{
    ;
}

void uartHWConfig(toml_table_t* mmio, char* p_name, const char* module_str, 
            toml_table_t* TablePtr, const char* table_str, int struct_i)
{
    CpeaUART uart;
    
    if (!getFifoSize(uart, TablePtr, struct_i)){
        fprintf(stderr, "Error in [mmio.%s.%s.hardware]\n", 
                p_name, module_str);        
        exit(1);
    } 
               
}  

int getFifoSize(CpeaUART uart, toml_table_t* TablePtr, int struct_i){
    
    const char *keyName;
    toml_datum_t fifoData;
    int i;
    
    for (i = 0; i < 2; i++){
        keyName = toml_key_in(TablePtr, 0);
        fifoData = toml_int_in(TablePtr, keyName);

        if (!fifoData.ok){
            fprintf(stderr, "[%s]: Value needs to be an integer\n",
                            keyName);
            return 0;                           
        } 

        else{
            if (fifoData.u.i < 1 || fifoData.u.i > 8192){
                fprintf(stderr, "[%s]: Value should be 1-8192\n"
                                "You entered %ld\n",
                                keyName, fifoData.u.i); 
                return 0;       
            }
        }
  
        if (!MMIO[struct_i]->uart)
            MMIO[struct_i]->uart = (CpeaUART*)calloc(1, sizeof(CpeaUART));  
        
        // RXFIFO
        if (i == 0){
            uart.rx_fifo = (uint16_t *)calloc(fifoData.u.i, (sizeof(uint16_t)));            
            MMIO[struct_i]->uart->rx_fifo = uart.rx_fifo;
            MMIO[struct_i]->uart->rxfifo_size = fifoData.u.i;
        }        
        // TXFIFO    
        else if (i == 1){            
            uart.tx_fifo = (uint16_t *)calloc(fifoData.u.i, (sizeof(uint16_t)));
            MMIO[struct_i]->uart->tx_fifo = uart.tx_fifo;
            MMIO[struct_i]->uart->txfifo_size = fifoData.u.i;                                   
        }
        
        // Technically an error
        else 
            return 0;    
    }
    return 1;       
}

// Filler. Does nothing right now.
void genericIntrConfig(toml_table_t* mmio, char* p_name, const char* module_str, 
            toml_table_t* table_ptr, const char* table_str, int struct_i)
{
    ;
}

void uartIntrConfig(toml_table_t* mmio, char* p_name, const char* module_str, 
            toml_table_t* IntrTable, const char* table_str, int struct_i)
{
    toml_table_t* uartTab;     // uart table
    toml_table_t* ModTab;      // uart module table
    toml_table_t* AddrTab;     // addr table
    toml_table_t* ResetTab;    // reset table
    
    // Retrieve 'addr' table for this peripheral
    uartTab = toml_table_in(mmio, p_name);
    ModTab = toml_table_in(uartTab, module_str);
    AddrTab = toml_table_in(ModTab, "addr");
    ResetTab = toml_table_in(ModTab, "reset");
 
    // XXX: I think this still works for the new TOML format
    if (!intr_alloc(IntrTable, struct_i)){
        fprintf(stderr, "Error in [mmio.%s.%s.interrupts]\n", 
                p_name, module_str);
        exit(1);    
    } 
        
    // RX Interrupt parsing
    if (!RXParse(IntrTable, AddrTab, ResetTab, RX, struct_i)){
        fprintf(stderr, "Error in [mmio.%s.%s.interrupts]\n", 
                p_name, module_str);
        exit(1);
    }

    // TX Interrupt parsing
    if (!TXParse(IntrTable, AddrTab, ResetTab, TX, struct_i)){
        fprintf(stderr, "Error in [mmio.%s.%s.interrupts]\n", 
                p_name, module_str);
        exit(1);
    }  
}

int RXParse(toml_table_t* IntrTable, toml_table_t* AddrTab, 
              toml_table_t* ResetTab, int intrType, int struct_i)
{

    toml_table_t* IntrTypeTable;
    const char* IntrName; 
    
    IntrName = toml_key_in(IntrTable, intrType);
    IntrTypeTable = toml_table_in(IntrTable, IntrName);
 
    // Skip if IRQ not enabled
    if(!checkIRQ(IntrName, intrType, 0, struct_i))
        return 1; 
    
    if (!GetEmuMode(IntrTypeTable, IntrName, intrType, struct_i))
        return 0;
    
    if (!IntrEnable(IntrTypeTable, IntrName, AddrTab, intrType, struct_i))
        return 0;
    
    if (!IntrDisable(IntrTypeTable, IntrName, AddrTab, intrType, struct_i))
        return 0;
        
    if (!IntrClear(IntrTypeTable, IntrName, AddrTab, intrType, struct_i))
        return 0;        
 
    if (!IntrStatus(IntrTypeTable, IntrName, AddrTab, intrType, struct_i))
        return 0; 
        
    if (!fifoTrigger(IntrTypeTable, IntrName, AddrTab, ResetTab, intrType, struct_i))
        return 0;     
 
    return 1;
}

int TXParse(toml_table_t* IntrTable, toml_table_t* AddrTab, 
              toml_table_t* ResetTab, int intrType, int struct_i)
{
    
    toml_table_t* IntrTypeTable;
    const char* IntrName; 
    
    IntrName = toml_key_in(IntrTable, intrType);
    IntrTypeTable = toml_table_in(IntrTable, IntrName);
     
    // Skip if IRQ not enabled
    if(!checkIRQ(IntrName, intrType, 0, struct_i))
        return 1;
 
    if (!GetEmuMode(IntrTypeTable, IntrName, intrType, struct_i))
        return 0;  
           
    if (MMIO[struct_i]->INTR[intrType]->mode == partial){
        fprintf(stderr, "[%s.Emulation_Mode]: TX interrupt must be done "
                        "in full emulation mode\n",
                        IntrName);
        return 0;                    
    }
        
    if (!IntrEnable(IntrTypeTable, IntrName, AddrTab, intrType, struct_i))
        return 0;
    
    if (!IntrDisable(IntrTypeTable, IntrName, AddrTab, intrType, struct_i))
        return 0;
        
    if (!IntrClear(IntrTypeTable, IntrName, AddrTab, intrType, struct_i))
        return 0;        
    
    if (!IntrStatus(IntrTypeTable, IntrName, AddrTab, intrType, struct_i))
        return 0; 
    
    if (!fifoFull(IntrTypeTable, IntrName, AddrTab, intrType, struct_i)){
        return 0;
    }
    
    if (!fifoSize(IntrTypeTable, IntrName, AddrTab, intrType, struct_i)){
        return 0;
    }

    if (!fifoCount(IntrTypeTable, IntrName, AddrTab, intrType, struct_i)){
        return 0;
    }
        
    if (!fifoTrigger(IntrTypeTable, IntrName, AddrTab, ResetTab, intrType, struct_i))
        return 0;               
            
    return 1;               
}                                          

toml_datum_t GetIntrData(toml_table_t* IntrTypeTable, toml_table_t* AddrTab, 
            const char *IntrName, const char *ConfigName, const char *dataKey)
{
    toml_datum_t AddrData;
    toml_datum_t IntrData;
    toml_table_t *RegConfigTable;
    
    char addrReg[20];
  
    // Commonly parsed data
    if (ConfigName){
        RegConfigTable = toml_table_in(IntrTypeTable, ConfigName);
        
        if (!strcmp(dataKey, "CR")){
            IntrData = toml_string_in(RegConfigTable, dataKey);
            if (!IntrData.ok){
                fprintf(stderr, "[%s.%s.%s]: Value needs to be a string\n"
                            "Please enter an existing register instead\n"
                            "Type \"none\" if you wish to skip\n",
                             IntrName, ConfigName, dataKey);
                return IntrData;
            }
            if (!strcmp(IntrData.u.s, "none")){
                return IntrData;    
            }
            else{           
                strcpy(addrReg, IntrData.u.s); 
                strcat(addrReg, "_addr");
                AddrData = toml_int_in(AddrTab, addrReg);
            
                if (!AddrData.ok){
                    fprintf(stderr, "[%s.%s.%s] does not exist in addr table\n"
                            "Please give register in format CR[n]\n"
                            "Type \"none\" if you wish to skip\n", 
                            IntrName, ConfigName, IntrData.u.s);
                    return AddrData;        
                }
                return IntrData;
            } 
                                             
        }
        else if (!strcmp(dataKey, "SR")){
            IntrData = toml_string_in(RegConfigTable, dataKey);
            if (!IntrData.ok){
                fprintf(stderr, "[%s.%s.%s]: Value needs to be a string\n"
                            "Please enter an existing register instead\n"
                            "Type \"none\" if you wish to skip\n",
                             IntrName, ConfigName, dataKey);
                return IntrData;
            }

            if (!strcmp(IntrData.u.s, "none")){
                return IntrData;    
            }
            else{            
                strcpy(addrReg, IntrData.u.s); 
                strcat(addrReg, "_addr");
                AddrData = toml_int_in(AddrTab, addrReg);        
                if (!AddrData.ok){
                    fprintf(stderr, "[%s.%s.%s] does not exist in addr table\n"
                            "Please give register in format SR[n]\n"
                            "Type \"none\" if you wish to skip\n", 
                            IntrName, ConfigName, IntrData.u.s);
                    return AddrData;        
                }
                return IntrData;
            }                         
        }
        else if (!strcmp(dataKey, "bit")){
            IntrData = toml_int_in(RegConfigTable, dataKey);
            if (!IntrData.ok){
                fprintf(stderr, "[%s.%s.%s]: Value needs to be a bit 0-31\n"
                            "You entered a string\n",
                            IntrName, ConfigName, dataKey);
                return IntrData;                
            }
            
            if (IntrData.u.i < 0 || IntrData.u.i > 31){
                fprintf(stderr, "[%s.%s.%s]: Bit value needs to be 0-31\n"
                                "You gave %ld\n",
                                IntrName, ConfigName, dataKey, IntrData.u.i);                
                return IntrData;
            }
        }
        else if (!strcmp(dataKey, "polarity")){
            IntrData = toml_int_in(RegConfigTable, dataKey);
            if (!IntrData.ok){
                fprintf(stderr, "[%s.%s.%s]: Value needs to be 0 or 1\n"
                            "You entered a string\n",
                            IntrName, ConfigName, dataKey);
                return IntrData;                
            }
            
            if (IntrData.u.i < 0 || IntrData.u.i > 1){
                fprintf(stderr, "[%s.%s.%s]: Value needs to be 0 or 1\n"
                                "You gave %ld\n",
                                IntrName, ConfigName, dataKey, IntrData.u.i);                
                return IntrData;
            }            
                        
        }
        
        // Interrupt specific data. Return it
        else{
            exit(1);
        }
    }
    
    // Interrupt specific data. Return it
    else{
        IntrData = toml_int_in(IntrTypeTable, dataKey);
        if (!IntrData.ok){
            IntrData = toml_string_in(IntrTypeTable, dataKey);
        }
    }
    
    return IntrData;    
}      

// Filler. Does nothing right now
void genericInterface(toml_table_t* mmio, char* p_name, const char* module_str, 
                toml_table_t* table_ptr, const char* table_str, int struct_i)
{
    ;
}

void uartInterface(toml_table_t* mmio, char* p_name, const char* module_str, 
                toml_table_t* table_ptr, const char* table_str, int struct_i)
{
    // Used to init char front end
    //Error *err;
    
    /* XXX: THIS WON'T WORK, because the serial_hd() global variable that is returned
    //      will be null. This is because our configuration code executes before
    //      command line options are parsed and therefore before the serial_hd() 
    //      global variable is initialized
    //      Need another solution if we wanna do this here
    */
    
    /*
    Chardev *chrdev;
        
    // 1) Setup serial chardev (Only 1)
    chrdev = serial_hd(0);
    
    // Allocate uart module, if not already allocated
    if (!MMIO[struct_i]->uart)
        MMIO[struct_i]->uart = (CpeaUART*)calloc(1, sizeof(CpeaUART));
        
    // 2) Assign serial Chardev to UART's Charbackend    
    if (!qemu_chr_fe_init(&MMIO[struct_i]->uart->chrbe, chrdev, &err)){
        printf("Failed to init Serial Chardev\n");
        exit(1);
    }         

    // 2) Set handlers for front-end 
    qemu_chr_fe_set_handlers(&MMIO[struct_i]->uart->chrbe, uart_can_receive, uart_receive,
                            uart_event, NULL, MMIO[struct_i], NULL, true); 
    */                          
        
}                                

int intr_alloc(toml_table_t* IntrTypeTable, int struct_i){

    int i;
    const char* IntrName;
    toml_table_t* RegConfigTable;
    toml_datum_t IRQn;
    
    // Loop through interrupts, checking IRQn, 
    for (i=0; ; i++){
        IntrName = toml_key_in(IntrTypeTable, i);
        if (!IntrName)
            break;
        
        RegConfigTable = toml_table_in(IntrTypeTable, IntrName);        
        IRQn = toml_int_in(RegConfigTable, "IRQn");
        
        // IRQn has not been configured
        if (!IRQn.ok){
            continue;    
        }
        
        // IRQn has integer in place
        else{
            if (IRQn.u.i < 0 || IRQn.u.i > 480){
                fprintf(stderr, "[%s.IRQn]: Entered invalid IRQn\n"
                                "Please enter an IRQn from 0 to 480\n",
                                IntrName);
                return 0;                
            }
            IRQtotal++;
            
            MMIO[struct_i]->INTR[i] = (interrupt *)calloc(1, sizeof(interrupt));
            MMIO[struct_i]->INTR[i]->irq_enabled = 1;
            MMIO[struct_i]->INTR[i]->irqn = IRQn.u.i;           
        }        
    }
    
    return 1;    
}

int checkIRQ(const char *IntrName, int intrType, int checkType, int struct_i){   

    enum {
        SKIP,
        ERR
    };
    
    switch (checkType){
    
    // Checking IRQ to skip configurations
    case SKIP:
    
        // IRQ not configured. Leave non-verbosely
        if (!MMIO[struct_i]->INTR[intrType]){
            return 0;
        }
        
        // IRQ configured. Continue peacefully
        else
            return 1;        
        break;
    
    // Checking IRQ to check for error condition    
    case ERR:
    
        // IRQ not configured. Complain
        if (!MMIO[struct_i]->INTR[intrType]){
            fprintf(stderr, "[%s.IRQn]: Can't configure interrupt if an IRQ isn't"
                        "configured\n",
                        IntrName);
            return 0;
        }
    
        // IRQ configured
        else
            return 1;    
        break;
        
    default:
        fprintf(stderr, "checkIRQ: checkType (%d) not implemented\n", checkType);
        exit(1);
        break;          
    } 
}

int GetEmuMode(toml_table_t* IntrTypeTable, const char *IntrName, 
        int intrType, int struct_i)
{

    toml_datum_t mode;
    mode = toml_string_in(IntrTypeTable, "Emulation_Mode");
    if (!mode.ok){
        fprintf(stderr, "[%s.Emulation_Mode]: Invalid format\n"
                        "Please enter a string for the emulation mode\n"
                        "The two modes are \"full\" and \"partial\"\n"
                        "You can skip by entering \"none\" in IRQn field\n",
                        IntrName);
        return 0;
    }
    else{
        if (!strcmp(mode.u.s, "full")){
            MMIO[struct_i]->INTR[intrType]->mode = 0;
        }
        else if (!strcmp(mode.u.s, "partial")){
            MMIO[struct_i]->INTR[intrType]->mode = 1;
        }
        else{
            fprintf(stderr, "[%s.Emulation_Mode]: Invalid option\n"
                        "The two modes are \"full\" and \"partial\"\n"
                        "You can skip by entering \"none\" in IRQn field\n",
                        IntrName);
            return 0;
        }        
    }
    
    return 1;    
}

int getRegAddr(toml_table_t* AddrTab, const char *IntrName,
            toml_datum_t IntrData)
{

    toml_datum_t data;
    int address;
    char addrReg[20];
    
    strcpy(addrReg, IntrData.u.s);
    strcat(addrReg, "_addr");
    data = toml_int_in(AddrTab, addrReg);
    if (!data.ok){
        fprintf(stderr, "[%s.%s]: Register doesn't exist in addr table\n"
                        "Provide a register that exists\n",
                        IntrName, IntrData.u.s);
        return 0;
    }    
    address = data.u.i;
    return address;

}

int getRegReset(toml_table_t* ResetTab, const char *IntrName,
            toml_datum_t IntrData)
{

    toml_datum_t data;
    int reset;
    char resetReg[20];
    
    strcpy(resetReg, IntrData.u.s);
    strcat(resetReg, "_reset");
    data = toml_int_in(ResetTab, resetReg);
    if (!data.ok){
        fprintf(stderr, "[%s.%s]: Register doesn't exist in reset table\n"
                        "Provide a register that exists\n",
                        IntrName, IntrData.u.s);
        return 0;
    }    
    reset = data.u.i;
    return reset;    

} 

int IntrEnable(toml_table_t* IntrTypeTable, const char *IntrName, 
        toml_table_t* AddrTab, int intrType, int struct_i)
{
    toml_datum_t RegData;
    toml_datum_t BitData;
    int addr; 
    int mode = MMIO[struct_i]->INTR[intrType]->mode;
            
    switch(mode){   
    case full:
        
        RegData = GetIntrData(IntrTypeTable, AddrTab, IntrName, "Intr_Enable", "CR");
        if (!RegData.ok)
            return 0;

        if (!strcmp(RegData.u.s, "none")){
            fprintf(stderr, "[%s.Intr_Enable.CR]: Can't skip this configuration in "
                            "full emulation mode\n"
                            "Set IRQn to \"none\" if you wish to skip this interrupt\n",
                            IntrName);
            return 0;
        }
        BitData = GetIntrData(IntrTypeTable, AddrTab, IntrName, "Intr_Enable", "bit");
        if (!BitData.ok)
            return 0;                    

        addr = getRegAddr(AddrTab, IntrName, RegData); 
         
        MMIO[struct_i]->INTR[intrType]->enable_addr = addr;         
        MMIO[struct_i]->INTR[intrType]->CRen = (atoi(RegData.u.s+2) - 1); 
        SET_BIT(MMIO[struct_i]->INTR[intrType]->enable_permit, BitData.u.i);
                       
        break;
        
    case partial:
        break;    
    
    default:
        break;    
    }
    
    return 1;    
}

int IntrDisable(toml_table_t* IntrTypeTable, const char *IntrName, 
        toml_table_t* AddrTab, int intrType, int struct_i)
{
    toml_datum_t RegData;
    toml_datum_t BitData;
    int addr; 
    int mode = MMIO[struct_i]->INTR[intrType]->mode;
            
    switch(mode){   
    case full:
        RegData = GetIntrData(IntrTypeTable, AddrTab, IntrName, "Intr_Disable", "CR");
        if (!RegData.ok)
            return 0;

        if (!strcmp(RegData.u.s, "none")){
            return 1;
        }        
        
        BitData = GetIntrData(IntrTypeTable, AddrTab, IntrName, "Intr_Disable", "bit");
        if (!BitData.ok)
            return 0;  
         
        addr = getRegAddr(AddrTab, IntrName, RegData); 
         
        MMIO[struct_i]->INTR[intrType]->disable_addr = addr; 
        MMIO[struct_i]->INTR[intrType]->CRdis = (atoi(RegData.u.s+2) - 1); 
        SET_BIT(MMIO[struct_i]->INTR[intrType]->disable_permit, BitData.u.i);
       
                       
        break;
        
    case partial:
        break;    
    
    default:
        break;    
    }
    
    return 1;  
}

int IntrClear(toml_table_t* IntrTypeTable, const char *IntrName, 
        toml_table_t* AddrTab, int intrType, int struct_i)
{
    toml_datum_t RegData;
    int addr;            

    RegData = GetIntrData(IntrTypeTable, AddrTab, IntrName, "Intr_Clear", "CR");
    if (!RegData.ok)
        return 0;

    if (!strcmp(RegData.u.s, "none")){
        return 1;
    }

    addr = getRegAddr(AddrTab, IntrName, RegData); 
    if (!addr)
        return 0;
                    
    MMIO[struct_i]->INTR[intrType]->clear_addr = addr; 
    
    return 1;  
}

int IntrStatus(toml_table_t* IntrTypeTable, const char *IntrName, 
        toml_table_t* AddrTab, int intrType, int struct_i)
{
    toml_datum_t RegData;
    toml_datum_t BitData; 
    int mode = MMIO[struct_i]->INTR[intrType]->mode;

    RegData = GetIntrData(IntrTypeTable, AddrTab, IntrName, "Intr_Status", "SR");
    if (!RegData.ok)
        return 0;

    BitData = GetIntrData(IntrTypeTable, AddrTab, IntrName, "Intr_Status", "bit");
    if (!BitData.ok)
        return 0;  
    
    // We configure the SR in either mode, when a user enters information for it
    // SR sometimes can't be skipped, even in partial mode        
    switch(mode){   
    case full:

        if (!strcmp(RegData.u.s, "none")){
            fprintf(stderr, "[%s.Intr_Status.SR]: Can't skip this configuration in "
                            "full emulation mode\n"
                            "Set IRQn to \"none\" if you wish to skip this interrupt\n",
                            IntrName);
            return 0;
        }
                 
        MMIO[struct_i]->INTR[intrType]->SRflg = (atoi(RegData.u.s+2) - 1); 
        SET_BIT(MMIO[struct_i]->INTR[intrType]->flag_permit, BitData.u.i);
                       
        break;
      
    case partial:
        if (!strcmp(RegData.u.s, "none"))
            return 1;
            
        MMIO[struct_i]->INTR[intrType]->SRflg = (atoi(RegData.u.s+2) - 1); 
        SET_BIT(MMIO[struct_i]->INTR[intrType]->flag_permit, BitData.u.i);
                        
        break;    
    
    default:
        break;    
    }
    
    return 1;  
}

int fifoFull(toml_table_t* IntrTypeTable, const char *IntrName, 
        toml_table_t* AddrTab, int intrType, int struct_i){

    toml_datum_t RegData;
    toml_datum_t BitData;
    toml_datum_t PolarityData; 
    int addr;

    RegData = GetIntrData(IntrTypeTable, AddrTab, IntrName, "FIFO_Full", "SR");
    if (!RegData.ok)
        return 0;

    if (!strcmp(RegData.u.s, "none"))
        return 1;

    addr = getRegAddr(AddrTab, IntrName, RegData);
    if (!addr)
        return 0;

    BitData = GetIntrData(IntrTypeTable, AddrTab, IntrName, "FIFO_Full", "bit");
    if (!BitData.ok)
        return 0;    

    PolarityData = GetIntrData(IntrTypeTable, AddrTab, IntrName, "FIFO_Full", "polarity");
    if (!PolarityData.ok)
        return 0;  
    
    MMIO[struct_i]->uart->SRtxff = (atoi(RegData.u.s+2) - 1);
    SET_BIT(MMIO[struct_i]->uart->txff_permit, BitData.u.i);     
    MMIO[struct_i]->uart->txff_addr = addr;
    MMIO[struct_i]->uart->txff_polarity = PolarityData.u.i;   

    return 1;
}

int fifoSize(toml_table_t* IntrTypeTable, const char *IntrName, 
        toml_table_t* AddrTab, int intrType, int struct_i){

    toml_datum_t RegData; 
    int SRindex;
    
    RegData = GetIntrData(IntrTypeTable, AddrTab, IntrName, "FIFO_Size", "SR");
    if (!RegData.ok)
        return 0;

    if (!strcmp(RegData.u.s, "none"))
        return 1;    
    
    MMIO[struct_i]->uart->SRtxf_size = (atoi(RegData.u.s+2) - 1);         
    SRindex = MMIO[struct_i]->uart->SRtxf_size;
        
    MMIO[struct_i]->SR[SRindex] = MMIO[struct_i]->uart->txfifo_size; 

    return 1;
}

int fifoCount(toml_table_t* IntrTypeTable, const char *IntrName, 
        toml_table_t* AddrTab, int intrType, int struct_i){

    toml_datum_t RegData;     
    int addr;
    
    RegData = GetIntrData(IntrTypeTable, AddrTab, IntrName, "FIFO_Count", "SR");
    if (!RegData.ok)
        return 0;

    if (!strcmp(RegData.u.s, "none"))
        return 1;    
    
    addr = getRegAddr(AddrTab, IntrName, RegData);
    if (!addr)
        return 0;
    
    MMIO[struct_i]->uart->SRtxf_cnt = (atoi(RegData.u.s+2) - 1);
    MMIO[struct_i]->uart->txf_cnt_addr = addr;             

    return 1;
}

int fifoTrigger(toml_table_t* IntrTypeTable, const char *IntrName, 
        toml_table_t* AddrTab, toml_table_t* ResetTab, 
        int intrType, int struct_i)
{
    toml_datum_t IntrData;
    int addr;
    int reset;    
    int mode = MMIO[struct_i]->INTR[intrType]->mode;
    
    IntrData = toml_int_in(IntrTypeTable, "Trigger"); 
 
    switch(mode){   
    case full:
        if (!IntrData.ok){
            IntrData = toml_string_in(IntrTypeTable, "Trigger");
            
            if (intrType == RX){
                if (!strcmp(IntrData.u.s, "none")){
                    fprintf(stderr, "[RX.Trigger]: Can't skip FIFO trigger "
                                    "for RX interrupt\n");
                    return 0;
                }
            }    
            else if (intrType == TX){
                if (!strcmp(IntrData.u.s, "none"))
                    return 1;
            }    
                        
            addr = getRegAddr(AddrTab, IntrName, IntrData);
            if (!addr)
                return 0; 
                             
            reset = getRegReset(ResetTab, IntrName, IntrData);
            if (!reset)
                return 0;
                
            MMIO[struct_i]->INTR[intrType]->trigger_addr = addr;
            MMIO[struct_i]->INTR[intrType]->trigger_val = reset;
                        
            free(IntrData.u.s);                    
        }
        else{
            if (intrType == RX){
                if (IntrData.u.i > 0 && IntrData.u.i <= MMIO[struct_i]->uart->rxfifo_size)
                    MMIO[struct_i]->INTR[intrType]->trigger_val = IntrData.u.i;  
                else{
                    fprintf(stderr, "[%s.Trigger]: Trigger size must be 1 to RXFIFO_Size\n"
                                    "You entered: %ld\n",
                                    IntrName, IntrData.u.i);   
                    return 0;
                }
            }
            else if (intrType == TX){
                if (IntrData.u.i > 0 && IntrData.u.i <= MMIO[struct_i]->uart->txfifo_size)
                    MMIO[struct_i]->INTR[intrType]->trigger_val = IntrData.u.i;  
                else{
                    fprintf(stderr, "[%s.Trigger]: Trigger size must be 1 to TXFIFO_Size\n"
                                    "You entered: %ld\n",
                                    IntrName, IntrData.u.i);   
                    return 0;
                }            
            }
            else
                return 0;                  
        }                    
        break;
    
    // XXX : TX interrupt will never execute here since partial 
    //       isn't allowed for it, but there is code for it anyway  
    case partial: 
               
        if (IntrData.ok){
            if (intrType == RX){
                if (IntrData.u.i > 0 && IntrData.u.i <= MMIO[struct_i]->uart->rxfifo_size)
                    MMIO[struct_i]->INTR[intrType]->trigger_val = IntrData.u.i;  
                else{
                    fprintf(stderr, "[%s.Trigger]: Trigger size must be 1 to RXFIFO_Size\n"
                                    "You entered: %ld\n",
                                    IntrName, IntrData.u.i);   
                    return 0;
                }
            }
            else if (intrType == TX){
                if (IntrData.u.i > 0 && IntrData.u.i <= MMIO[struct_i]->uart->txfifo_size)
                    MMIO[struct_i]->INTR[intrType]->trigger_val = IntrData.u.i;  
                else{
                    fprintf(stderr, "[%s.Trigger]: Trigger size must be 1 to TXFIFO_Size\n"
                                    "You entered: %ld\n",
                                    IntrName, IntrData.u.i);   
                    return 0;
                }            
            }
            else
                return 0;               
        }
        else{    
            fprintf(stderr, "[%s.Trigger]: Can't use string here for partial emulation\n"
                            "Please use integer value instead\n",
                            IntrName);
            return 0;
        }                  
        break;    
    
    default:
        break;    
    }
    
    return 1; 
}

void error(const char *msg, const char *msg1, const char *msg2, const char *msg3)
{
	fprintf(stderr, "ERROR: %s%s%s%s\n", msg, msg1?msg1:"", msg2?msg2:"", msg3?msg3:"");
	exit(1);
}
