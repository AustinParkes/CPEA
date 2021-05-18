/* Parse emulatorConfig.toml and extract values important for the emulator 
 *
 *
*/

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "emulatorConfig.h"
#include "toml.h"

static void error(const char *msg, const char* msg1)
{
	fprintf(stderr, "ERROR: %s%s\n", msg, msg1?msg1:"");
	exit(1);
}

// Read config file and parse emulator configurations
void emuConfig(){
	
	FILE *fp;
	char errbuf[200];

	/*
		Read and Parse configuration file
	*/
	
	fp = fopen("emulatorConfig.toml", "r");
	
    if (!fp) {
        error("cannot open emulatorConfig.toml - ", strerror(errno));
    }
    
    // Root table 
    toml_table_t* config = toml_parse_file(fp, errbuf, sizeof(errbuf));
    fclose(fp);
   	if (!config){
   		error("cannot parse emulatorConfig.toml - ", errbuf);
   	}
   	
    /*
    	Traverse to [mem_map] table
    */
 	toml_table_t* mem_map = toml_table_in(config, "mem_map");
 	if (!mem_map){
 		error("missing [mem_map]", "");
 	} 
 	
    /*
    	Extract values from memory map
    */
    
    // flash address
    toml_datum_t flash_addr = toml_int_in(mem_map, "flash_addr");
    if (!flash_addr.ok){
    	error("Cannot read mem_map.flash_addr", "");
    }
    FLASH_ADDR = (uint32_t)flash_addr.u.i;   // Get integer from union  
    
    // flash size
    toml_datum_t flash_size = toml_int_in(mem_map, "flash_size");
    if (!flash_size.ok){
    	error("Cannot read mem_map.flash_size", "");
    }
    FLASH_SIZE = (uint32_t)flash_size.u.i;     
    
    // sram addr
    toml_datum_t sram_addr = toml_int_in(mem_map, "sram_addr");
    if (!sram_addr.ok){
    	error("Cannot read mem_map.sram_addr", "");
    }
    SRAM_ADDR = (uint32_t)sram_addr.u.i;   
    
    // sram size
    toml_datum_t sram_size = toml_int_in(mem_map, "sram_size");
    if (!sram_size.ok){
    	error("Cannot read mem_map.sram_size", "");
    }
    SRAM_SIZE = (uint32_t)sram_size.u.i;    
    
    /*
    	Done reading general memory map information
    	Traverse to [mem_map.mmio] table
    */
    
	// mmio == mem_map.mmio
 	toml_table_t* mmio = toml_table_in(mem_map, "mmio");
 	if (!mmio){
 		error("missing [mem_map.mmio]", "");
 	}
    
    // mmio start
    toml_datum_t mmio_start = toml_int_in(mmio, "mmio_start");
    if (!mmio_start.ok){
    	error("Cannot read mmio.mmio_start", "");
    }
    MMIO_START = (uint32_t)mmio_start.u.i; 
    
    // mmio size
    toml_datum_t mmio_size = toml_int_in(mmio, "mmio_size");
    if (!mmio_size.ok){
    	error("Cannot read mmio.mmio_size", "");
    }
    MMIO_SIZE = (uint32_t)mmio_size.u.i;  
       
    /*
    	Done reading mmio information
    	Traverse to [firmware] table
    */
    
	
 	toml_table_t* firmware = toml_table_in(config, "firmware");
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
    toml_datum_t entry = toml_int_in(execution, "entry");
    if (!entry.ok){
    	error("Cannot read execution.entry", "");
    }
    START = (uint32_t)entry.u.i; 
    
 	// end of execution
    toml_datum_t end = toml_int_in(execution, "end");
    if (!end.ok){
    	error("Cannot read execution.end", "");
    }
    END = (uint32_t)end.u.i;         	
    
    /***********************************
		Finish General Emulator configs.
		Begin Peripheral Configs    
    ************************************/

    /*
    	UART config
    	1) Generate UART struct for each module from [memory_map.mmio]
    	2) Traverse to [mmio.uart] and extract config values to UART struct(s)
    	TODO: Turn each periph config into a function.
    */
    
    /* 1) Generate UART struct for each UART module */
    
    // TODO: What if there are 0 modules entered. (If in function, we could just leave function)
    // TODO: Put Limit of 99 on uart_count
    // Get number of UART modules
    int uart_count;
    toml_datum_t num_uarts = toml_int_in(mmio, "uart_count");
    if (!num_uarts.ok){
    	error("Cannot read mmio.uart_count", "");
    }
    uart_count = (int)num_uarts.u.i;					// Number of UART modules the user specified.
	
	// Generate UART structs
	//USART_handle *UART_test[uart_count];   				// Create array of pointers to structs
	
	// Allocate space for each struct. TODO: Must free these after emulation finished.
	for (int i=0; i<uart_count; i++){
    	UART_test[i] = (USART_handle *)malloc(sizeof(USART_handle));
    	if (UART_test[i] == NULL)
    		error("UART struct memory not allocated","");
    }
 	
 	
    /* 2) Extract UART config values to UART structs */
    toml_table_t* uart = toml_table_in(mmio, "uart");   // Use mmio pointer from earlier
 	if (!uart){
 		error("missing [mmio.uart]", "");
 	}
 	
 	// Check if UART module exists and how many. "tab_i" keeps track of the number of modules.
 	/*
 		Eventually, may need to check for an 8-bit mode to use 8 bit structures instead. 
 	*/
 	/* Would need to generate a new UART struct for each module that exists.
 	   Could use malloc to generate enough structs for whatever the user specifies	
 	*/ 
 	for (int tab_i=0; ; tab_i++){   
 	
 		// Get the name of the current UART module    
    	const char* uart_module = toml_key_in(uart, tab_i);
    	if (!uart_module){
    		break;				
    	} 
    	printf("uart_module: %d: %s\n", tab_i, uart_module); 
    	
    	// Get the current UART table from the name
    	toml_table_t* uartx = toml_table_in(uart, uart_module);
    	if (!uartx){
 			error("Failed to get UART table from module %s", uart_module);
 		}
 		
 		// Get ptr to current UART struct
 		uint32_t *UART_ptr = (uint32_t *)UART_test[tab_i];
 		            	
 		if (!UART_ptr)
 			error("Failed to get pointer from current UART struct", "");
 		
    	// Fill UART struct with current UART module configuration values   
    	for (int key_i=0; ; key_i++){
    		const char* key = toml_key_in(uartx, key_i);
    		if (!key) break;
    		printf("key %d: %s: ", key_i, key);
    		
    		// Get data from the current key
    		toml_datum_t key_data = toml_int_in(uartx, key);
    		if (!key_data.ok){
    			error("Cannot read key data", "");
    		}
    		
    		// Store config data to current UART member
    		*UART_ptr = (uint32_t)key_data.u.i;
    		UART_ptr++;							// TODO: Make sure this doesn't go into another structs space or out of bounds
    		printf("0x%lx\n", key_data.u.i);	
        }
        
   	}	
    	 
    	    	            
    /*
    	Free Memory for the file
    */
    toml_free(config);
    
}
