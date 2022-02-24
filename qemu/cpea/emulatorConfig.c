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
 *                             
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
	//int init_i;                 // Index to initialize MMIO struct.	           
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
    //int has_irq;            // Store if irq exists or not
    //int irqn;               // Store irqn
    
    char reg_type[4];       // Helps determine register type
    //const char *has_irq_s;  // Store boolean string for irq     	
    const char* key_str;	// Store name of any key 	  
 	
    //toml_table_t* irq_ptr;	// ptr to irq inline table
    //toml_datum_t irq_true;  // irq enabled for peripheral
    //toml_datum_t irqn_key;  // Defines IRQn  
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
		
		
		/*
		key_str = toml_key_in(table_ptr, 4);
		if (!key_str){
            fprintf(stderr, "ERROR: Missing irq table in [mmio].[%s].[%s].[%s]\n", p_name, module_str, table_str);
            exit(1);	
    	}	    	
    	irq_ptr = toml_table_in(table_ptr, key_str);
    	   	
    	// Default irq info   	
    	MMIO[struct_i]->irq_enabled = 0;
    	MMIO[struct_i]->irqn = 0xffff; 
    	// Parse 'true' key 
    	irq_true = toml_int_in(irq_ptr, "enabled");
  	    	
        // User didn't enter integer
    	if (!irq_true.ok){    	    
  	        irq_true = toml_string_in(irq_ptr, "enabled"); 	         
  	        if(!irq_true.ok){
  	            fprintf(stderr, "ERROR: Bad data for \"true\" in [mmio.%s.%s.%s.irq]\n", p_name, module_str, table_str);
                exit(1);  
  	        }
  	        
  	        // String entered   	        
  	        has_irq_s = irq_true.u.s;
  	        if (!strcmp(has_irq_s, "false"))
  	            has_irq = 0;
  	        else if (!strcmp(has_irq_s, "true"))
  	            has_irq = 1;
  	        else{
  	            fprintf(stderr, "ERROR: Must use boolean for \"true\" in [mmio.%s.%s.%s.irq]\n", p_name, module_str, table_str);
                exit(1);    	        
  	        }
  	        free(irq_true.u.s);       
    	}
    	
    	// User entered integer
    	else{
            has_irq = irq_true.u.i;
            if (has_irq < 0 || has_irq > 1){
  	            fprintf(stderr, "ERROR: Must use boolean for \"true\" in [mmio.%s.%s.%s.irq]\n", p_name, module_str, table_str);
                exit(1);                 
            }
    	}
        
        // Parse 'irqn' key
        if (has_irq){
        
            IRQtotal = IRQtotal + 1;    // Global counter
        
            irqn_key = toml_int_in(irq_ptr, "irqn");
            if (!irqn_key.ok){
        	    fprintf(stderr, "ERROR: [mmio.%s.%s.%s.irq] has an irq enabled, but no IRQn\n", p_name, module_str, table_str);
                exit(1);           
            }                
            irqn = irqn_key.u.i;
            if (irqn < 0 || irqn > 480){
        	    fprintf(stderr, "ERROR: [mmio.%s.%s.%s.irq] must have irqn in range [0, 480]\n", p_name, module_str, table_str);
                exit(1);              
            }
            
            // Update irq info for this module
            MMIO[struct_i]->irq_enabled = 1;
            MMIO[struct_i]->irqn = irqn;
        }  
        */  	
			
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

    keyName = toml_key_in(TablePtr, 0);
    fifoData = toml_int_in(TablePtr, keyName);

    // String entered. Complain
    if (!fifoData.ok){
        fprintf(stderr, "[%s]: Value needs to be an integer\n",
                        keyName);
        return 0;                           
    } 
    // Integer entered
    else{
        if (fifoData.u.i < 1 || fifoData.u.i > 1024){
            fprintf(stderr, "[%s]: Value should be 1-1024\n"
                            "You entered %ld\n",
                            keyName, fifoData.u.i); 
            return 0;       
        }
    }
       
    uart.rx_fifo = (uint8_t *)calloc(fifoData.u.i, (sizeof(uint8_t)));
    uart.rxfifo_size = fifoData.u.i;
    
    if (!MMIO[struct_i]->uart)
        MMIO[struct_i]->uart = (CpeaUART*)calloc(1, sizeof(CpeaUART));
            
    MMIO[struct_i]->uart->rx_fifo = uart.rx_fifo;
    MMIO[struct_i]->uart->rxfifo_size = uart.rxfifo_size;
    
    return 1;       
}

// Filler. Does nothing right now.
void genericIntrConfig(toml_table_t* mmio, char* p_name, const char* module_str, 
            toml_table_t* table_ptr, const char* table_str, int struct_i)
{
    ;
}

void uartIntrConfig(toml_table_t* mmio, char* p_name, const char* module_str, 
            toml_table_t* TablePtr, const char* table_str, int struct_i)
{
    toml_table_t* uartTab;     // uart table
    toml_table_t* ModTab;      // uart module table
    toml_table_t* AddrTab;      // addr table
    
    // Retrieve 'addr' table for this peripheral
    uartTab = toml_table_in(mmio, p_name);
    ModTab = toml_table_in(uartTab, module_str);
    AddrTab = toml_table_in(ModTab, "addr");
 
    if (!intr_alloc(TablePtr, struct_i)){
        fprintf(stderr, "Error in [mmio.%s.%s.interrupts]\n", 
                p_name, module_str);
        exit(1);    
    } 
 
    // TODO: Need to fix RXFFParse API to match the new interrupt scheme
    // TODO: Also need to fix the cpea.c emulation to match the new interrupt scheme ...
    // RXFIFO Interrupt parsing
    if (!RXFFParse(TablePtr, AddrTab, RXFF, struct_i)){
        fprintf(stderr, "Error in [mmio.%s.%s.interrupts]\n", 
                p_name, module_str);
        exit(1);
    }
  
    
}

int RXFFParse(toml_table_t* TablePtr, toml_table_t* AddrTab, 
              int intrType, int struct_i)
{

    toml_table_t* IntrConfig;   // Inline Table for the Interrupt
    const char* IntrName;       // Interrupt Name for inline table       
    
    int userType;                // String (1) or integer (2)
    int bitType;                // String (1) or integer (2)
    toml_datum_t RegData;       // Register data from an interrupt table key
    toml_datum_t BitData;       // Bit data from an interrupt table key
    int status;                 // Invalid (0), exists (1), or no register (2)
    
    int address;                // 'Trigger' register address
    int reset;                  // 'Trigger' register reset
    
    // Check if IRQ enabled
      
    
    IntrName = toml_key_in(TablePtr, intrType);
    IntrConfig = toml_table_in(TablePtr, IntrName);
    
    /*** CR_enable ***/
    /* XXX: One of these days, might be able to turn CR/SR parsing 
            into a function if it's repeatedly used
            For now, use the low-level functions.
              
    */
    
    
    
    // Get data type user entered
    userType = CheckIntrData(IntrConfig, IntrName, "CR_enable", REG);
    if (!userType)
        return 0;
    
    bitType = CheckIntrData(IntrConfig, IntrName, "CRbit", BIT);
    if (!bitType)
        return 0;
    
    // Get register data itself
    RegData = GetIntrData(IntrConfig, IntrName, "CR_enable", userType, REG);

    // Check what user entered in register field
    status = CheckIntrReg(RegData, AddrTab, IntrName, "CR_enable", intrType, struct_i);
    if (!status)
        return 0;    
        
    // Register entered and exists
    else if (status == 1){
        // Get bit data, while checking if its valid
        BitData = GetIntrData(IntrConfig, IntrName, "CRbit", bitType, BIT);
        if (!BitData.ok)
            return 0;
            
        // Configure the interrupt
        
        // Enable emulation
        MMIO[struct_i]->INTR[intrType]->enabled = 1;
        // Set CR_enable
        SET_BIT(MMIO[struct_i]->INTR[intrType]->CR_enable, BitData.u.i);
        // Get CR index   
        MMIO[struct_i]->INTR[intrType]->CR_i = (atoi(RegData.u.s+2) - 1);        
        MMIO[struct_i]->INTR[intrType]->mode = full;    
        // Free toml string
        free(RegData.u.s);         
    }
        
    // Partial emulation
    else if (status == 2){
        MMIO[struct_i]->INTR[intrType]->enabled = 1;                    
        MMIO[struct_i]->INTR[intrType]->mode = partial;        
    }
        
    // Leave, interrupt not being configured
    else 
        return 1;              
            
    /*** SR_set ***/
    
    // Get data type user entered
    userType = CheckIntrData(IntrConfig, IntrName, "SR_set", REG);
    if (!userType)
        return 0;

    
    bitType = CheckIntrData(IntrConfig, IntrName, "SRbit", BIT);
    if (!bitType)
        return 0;     
     
    // Get register data itself
    RegData = GetIntrData(IntrConfig, IntrName, "SR_set", userType, REG);
    
    // Check if register exists that the user entered
 
    status = CheckIntrReg(RegData, AddrTab, IntrName, "SR_set", intrType, struct_i);
    if (!status)
        return 0;    
        
    // register entered and exists
    else if (status == 1){
        // Get bit data, while checking if its valid
        BitData = GetIntrData(IntrConfig, IntrName, "SRbit", bitType, BIT);
        if (!BitData.ok)
            return 0;
            
        // Configure the interrupt   
        SET_BIT(MMIO[struct_i]->INTR[intrType]->SR_set, BitData.u.i);        
        MMIO[struct_i]->INTR[intrType]->SR_i = (atoi(RegData.u.s+2) - 1);            
        free(RegData.u.s);
            
    }
        
    // Skip
    else{
        // Don't want to be here during full emulation
        if(!checkPartial(IntrName, "SR_set", intrType, struct_i))
            return 0;
    }        

    
    /** Trigger **/

    userType = CheckIntrData(IntrConfig, IntrName, "Trigger", REG);
    if (!userType)
        return 0;
        
    // Get register data itself
    RegData = GetIntrData(IntrConfig, IntrName, "Trigger", userType, REG);             
    
    // Check if register exists that the user entered
    if (userType == STRING){  
        status = CheckIntrReg(RegData, AddrTab, IntrName, "Trigger", intrType, struct_i);
        if (!status)
            return 0;    
        
        // register entered and status
        else if (status == 1){ 
                   
            // 'Trigger' Address
            address = getRegAddr(RegData, AddrTab);  
            MMIO[struct_i]->INTR[intrType]->Trigger_addr = address;
            
            // 'Trigger' Reset value
            reset = getRegReset(RegData, AddrTab);
            MMIO[struct_i]->INTR[intrType]->Trigger_val = reset;
            free(RegData.u.s);
        
        }
        
        // Default to Trigger = 1
        else
            MMIO[struct_i]->INTR[intrType]->Trigger_val = 1;
      
    }
    
    // Configure no matter what
    else if (userType == INTEGER)
        MMIO[struct_i]->INTR[intrType]->Trigger_val = RegData.u.i;                          
       
        
  
    return 1;
}


int CheckIntrData(toml_table_t* InlineTable, const char *InlineTableName,
             const char *InlineTableKey, int dataRep){

    int dType;                  // Data type entered by user (String/Integer) 
    toml_datum_t KeyData;       // Data inside inline table
    char regType[3];
    
    KeyData = toml_string_in(InlineTable, InlineTableKey);
    
    strncpy(regType, InlineTableKey, 2);
    
    // String not entered
    if (!KeyData.ok){
        KeyData = toml_int_in(InlineTable, InlineTableKey);
        if (!KeyData.ok){
  	        fprintf(stderr, "Bad data for [%s.%s]\n",
  	                        InlineTableName, InlineTableKey);
            dType = 0;              
        } 
               
        // Integer entered
        else{
            // Bit
            if (dataRep == BIT){
                dType = INTEGER;
            }
            // Register
            else{
                // XXX: Value can't be integer for keys that start with "CR" or "SR"
                if (!strncmp(InlineTableKey, "CR", 2) ||
                    !strncmp(InlineTableKey, "SR", 2))
                {    
                    fprintf(stderr, "[%s.%s]: Value needs to be a string\n"
                                "You entered an integer: %ld\n",
                                InlineTableName, InlineTableKey, KeyData.u.i);    
                    dType = 0;
                }
                else
                    dType = INTEGER;
            }    
        }    
    }
    
    // String entered
    else{
        // Bit
        if (dataRep == BIT){
            fprintf(stderr, "[%s.%s]: Value needs to be an integer\n"
                            "You entered a string: %s\n",
                            InlineTableName, InlineTableKey, KeyData.u.s);
            dType = 0;    
        }
        // Register
        else
            dType = STRING;
    }
      
    // 0-Error, 1-String, 2-Integer   
    return dType;
}

toml_datum_t GetIntrData(toml_table_t* InlineTable, const char *InlineTableName, 
                    const char *InlineTableKey, int dataType, int dataRep)
{

    toml_datum_t IntrData;

    // Retrieve string
    if (dataType == STRING){
    
        IntrData = toml_string_in(InlineTable, InlineTableKey);
                        
        // Trying to retrieve bit data. Programmer error    
        if (dataRep == BIT){
            fprintf(stderr, "[%s.%s]: Value needs to be a bit 0-31\n"
                            "You entered a string\n",
                            InlineTableName, InlineTableKey);
            exit(1);
        }
            
    }
    
    // Retrieve integer
    else if (dataType == INTEGER){
        IntrData = toml_int_in(InlineTable, InlineTableKey);   
        if (dataRep == BIT){
            if (IntrData.u.i < 0 || IntrData.u.i > 31){
                fprintf(stderr, "[%s.%s]: Bit value needs to be 0-31\n"
                                "You gave %ld\n", 
                                InlineTableName, InlineTableKey, IntrData.u.i);
  	                        
  	            IntrData.ok = 0;            
  	        }                                        
        }     
    }
      
    return IntrData;
}                

// Only works for CR_enable and SR_set
int CheckIntrReg(toml_datum_t IntrData, toml_table_t* AddrTab, 
                const char *InlineTableName, const char *InlineTableKey,
                int intrType, int struct_i)
{

        toml_datum_t AddrData;
        char regType[3];
        // TODO: Dangerous, need to use safer str functions
        char addrReg[20];           // Name of an address register
        
        // Nothing entered. Do nothing
        if (!strcmp(IntrData.u.s, "reg"))
            return 3;
            
        // Register entered    
        else if (!strncmp(IntrData.u.s, "CR", 2) || 
            !strncmp(IntrData.u.s, "SR", 2))
        {
            // Get the register type, by its first 2 letters
            strncpy(regType, IntrData.u.s, 2);
            
            // Check if register matches an existing register in address table
            strcpy(addrReg, IntrData.u.s);
            strcat(addrReg, "_addr");
            AddrData = toml_int_in(AddrTab, addrReg);
            
            // Register doesn't exist in 'addr' table           
            if (!AddrData.ok){
                fprintf(stderr, "[%s.%s.%s] does not exist in addr table\n"
                        "Please give register in format %s[n]\n", 
                        InlineTableName, InlineTableKey, 
                        IntrData.u.s, regType);
                return 0;
            }
            
            // If interrupt allocated, Complain if partial emulation enabled.
            if (MMIO[struct_i]->INTR[intrType]){
                if (MMIO[struct_i]->INTR[intrType]->mode == partial &&
                    strncmp(InlineTableKey, "SR", 2))
                {
                    fprintf(stderr, "[%s.%s]: Can't emulate some registers when\n"
                                    "partial emulation is enabled\nPlace "
                                    "\"reg\" to skip checking the field\n",
                                    InlineTableName, InlineTableKey);
                    return 0;                
                }
            }
            
            return 1;                                 
        }
        
        // Partial emulation
        else if(!strcmp(IntrData.u.s, "partial")){
            return 2;
        }
        
        // Invalid register format. Complain
        else{
            fprintf(stderr, "[%s.%s]: Either invalid register format\n"
                            "or \"partial\" entered incorrectly\n"
                            "Please give registers in format %s[n]\n",
                            InlineTableName, InlineTableKey, regType);
            return 0;
        } 
                       
}

// Check if CR is enabled during SR
int checkPartial(const char *InlineTableName, const char *InlineTableKey,
            int intrType, int struct_i)
{
    // Not doing partial emulation
    if (MMIO[struct_i]->INTR[intrType]->mode == 0){
        fprintf(stderr, "[%s.%s]: Can't skip if a control register"
                    "is configured\nCan skip if doing partial emulation\n",
                    InlineTableName, InlineTableKey);
        return 0;    
    }
    
    // Doing partial emulation
    else
        return 1;
            
}

// Get a registers address value. Already established it exists
int getRegAddr(toml_datum_t IntrData, toml_table_t* AddrTab)
{

    toml_datum_t data;
    int address;
    char addrReg[20];           // Name of an address register
    
    strcpy(addrReg, IntrData.u.s);
    strcat(addrReg, "_addr");
    data = toml_int_in(AddrTab, addrReg);
    
    address = data.u.i;
    return address;

}

// Get a registers reset value. Already established it exists
int getRegReset(toml_datum_t IntrData, toml_table_t* AddrTab)
{

    toml_datum_t data;
    int reset;
    char resetReg[20];           // Name of an reset register
    
    strcpy(resetReg, IntrData.u.s);
    strcat(resetReg, "_reset");
    data = toml_int_in(AddrTab, resetReg);
    
    reset = data.u.i;
    return reset;    

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

int intr_alloc(toml_table_t* TablePtr, int struct_i){

    int i;
    const char* IntrName;
    toml_table_t* IntrTable;
    toml_datum_t IRQn;
    
    // Loop through interrupts, checking IRQn, 
    for (i=0; ; i++){
        IntrName = toml_key_in(TablePtr, i);
        if (!IntrName)
            break;
        
        IntrTable = toml_table_in(TablePtr, IntrName);        
        IRQn = toml_int_in(IntrTable, "IRQn");
        
        // IRQn has not been configured
        if (!IRQn.ok){
            continue;    
        }
        
        // IRQn has integer in place
        // XXX: Need to know the interrupt type we are on so we can assign a key index for it 
        else{
            // TODO: Ensure IRQ is a valid value here
            if (IRQn.u.i < 0 || IRQn.u.i > 480){
                fprintf(stderr, "[%s.IRQn]: Entered invalid IRQn\n"
                                "Please enter an IRQn from 0 to 480\n",
                                IntrName);
                return 0;                
            }
            IRQtotal++;
            
            // TODO: Allocate interrupt for the index we are on 
            MMIO[struct_i]->INTR[i] = (interrupt *)calloc(1, sizeof(interrupt));
            
            // TODO: Initialize IRQ information
            MMIO[struct_i]->INTR[i]->irq_enabled = 1;
            MMIO[struct_i]->INTR[i]->irqn = IRQn.u.i;           
        }        
    }
    
    return 1;    
}

void error(const char *msg, const char *msg1, const char *msg2, const char *msg3)
{
	fprintf(stderr, "ERROR: %s%s%s%s\n", msg, msg1?msg1:"", msg2?msg2:"", msg3?msg3:"");
	exit(1);
}
