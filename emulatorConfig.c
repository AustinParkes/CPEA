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

static void error(const char *msg, const char* msg1)
{
	fprintf(stderr, "ERROR: %s%s\n", msg, msg1?msg1:"");
	exit(1);
}

// Read config file, parse emulator configurations, and configure emulator
void emuConfig(uc_engine *uc, char *arm_code, char *arm_data){
 	
 	/***********************************
		Parse Configuration File and Store configurations   
    ************************************/ 	  
    toml_table_t* mmio;		// mmio table from TOML file.    
	FILE *fp;				
	char errbuf[200];

	printf("Configure Emulator\n");	
	
	fp = fopen("emulatorConfig.toml", "r");	
    if (!fp) {
        error("cannot open emulatorConfig.toml - ", strerror(errno));
    }
    
    // Root table 
    toml_table_t* root_table = toml_parse_file(fp, errbuf, sizeof(errbuf));
    fclose(fp);
   	if (!root_table){
   		error("cannot parse emulatorConfig.toml - ", errbuf);
   	}    
    
    // Gather and Store data from emulatorConfig.toml     	
    mmio = parseTOML(root_table);
    
    
    /***********************************
		General Emulator Configurations.   
    ************************************/
    
    // Memory Map for Emulator
    map_memory(uc);
    
    // Init ARM Registers (includes SP, LR)
    // TODO: See if there is a more legitimate way to init SP.
    reg_init(uc);
    
    /***********************************
		Peripheral Configurations   
    ************************************/
	uartConfig(uc, mmio);
       	     	    	            
    /*** Free Memory for config file ***/
    free(root_table); 
      
    printf("   - Complete\n");         
}


toml_table_t* parseTOML(toml_table_t* root_table){
	
    /*
    	Traverse to [mem_map] table
    */
 	toml_table_t* mem_map = toml_table_in(root_table, "mem_map");
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
    toml_datum_t mmio_addr = toml_int_in(mmio, "mmio_addr");
    if (!mmio_addr.ok){
    	error("Cannot read mmio.mmio_addr", "");
    }
    MMIO_ADDR = (uint32_t)mmio_addr.u.i; 
    
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
    
    return mmio;

}

void map_memory(uc_engine *uc){

	// Map Flash region
	if (uc_mem_map(uc, FLASH_ADDR, FLASH_SIZE, UC_PROT_ALL)){
		printf("Failed to map flash region to memory. Quit\n");
		exit(1);
	}
	
	// Map SRAM region
	if (uc_mem_map(uc, SRAM_ADDR, SRAM_SIZE, UC_PROT_ALL)){
		printf("Failed to map sram region to memory. Quit\n");
		exit(1);	
	}	
		
	// Map all MMIO from 0x40000000 - 0x5FFFFFFF
	if (uc_mem_map(uc, MMIO_ADDR, MMIO_SIZE, UC_PROT_ALL)){
		printf("Failed to map MMIO region to memory. Quit\n");
		exit(1);
	}
	
}

void reg_init(){

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
	FP = SRAM_ADDR + SRAM_SIZE - 0x1000;	// r11  
	r_r12 = 0x000C;    	// r12
	SP = FP;      		// r13 
	 
}

// Configure UART emulation
int uartConfig(uc_engine *uc, toml_table_t* mmio){

	uint32_t *UART_data;		// Points to any given UART struct, and is used to iterate through their data

	// These keep track of the callback range for UART register accesses.
	minUARTaddr = 0xFFFFFFFF;	// Chose a value that we know is larger than the greatest UART addr
	maxUARTaddr = 0;					
	
	UART_enable = false;   			// UART is disabled by default
	
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

    toml_datum_t num_uarts = toml_int_in(mmio, "uart_count");
    if (!num_uarts.ok){
    	error("Cannot read mmio.uart_count", "");
    }
    uart_count = (int)num_uarts.u.i;					// Number of UART modules the user specified.

	// Allocate space for each struct. TODO: Must free these after emulation finished.
	
	for (int i=0; i<uart_count; i++){
    	UART[i] = (UART_handle *)malloc(sizeof(UART_handle));
    	if (UART[i] == NULL){
    		printf("UART struct memory not allocated for UART%d\n", i);
    	}
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
    	if (!uart_module) 
    		break;
    						
    	//printf("uart_module: %d: %s\n", tab_i, uart_module); 
    	
    	// Get the current UART table from the name
    	toml_table_t* uartx = toml_table_in(uart, uart_module);
    	if (!uartx){
 			error("Failed to get UART table from module %s", uart_module);
 		}
 		
 		// Get ptr to current UART struct data. Also serves as a reset to reuse the struct.
 		//uint32_t *UART_data = (uint32_t *)UART;
 		
 		// Get ptr to current UART struct data. 
 		UART_data = (uint32_t *)UART[tab_i];
 		            	
 		if (!UART_data)
 			error("Failed to get pointer from current UART struct", "");
 		
    	// Fill UART struct with current UART module configuration values   
    	for (int key_i=0; ; key_i++){
    		const char* key = toml_key_in(uartx, key_i);
    		if (!key) 
    			break;
    			
    		
    		
    		// Get data from the current key
    		toml_datum_t key_data = toml_int_in(uartx, key);
    		if (!key_data.ok){
    			error("Cannot read key data", "");
    		}
    		
    		// Initialize UART structs with peripheral register addresses and reset values
    		uint32_t base_addr;
			if (key_i == 0)
    			base_addr = (uint32_t)key_data.u.i;				// Base ADDR should be the first key we access.
    				
    		//*UART_ptr = (uint32_t)key_data.u.i;
    		*UART_data = (uint32_t)key_data.u.i;
    		
			//if (*UART_data < base_addr && key_i <= 11)			// Convert addr offsets to full addresses. 11 registers pre-determined.
			//	*UART_data = *UART_data + base_addr;
			
			// Convert offset address to absolute address.
			// NOTE: First 11 registers are the address registers.
			if (*UART_data < base_addr && key_i <= 11){			// Convert addr offsets to full addresses. 11 registers pre-determined.
				*UART_data = *UART_data + base_addr;
			
				// Keep track of lowest and highest UART addresses to determine callback range later.
				if (*UART_data < minUARTaddr)
					minUARTaddr = *UART_data;						// Update the lowest address thus far.
				else if (*UART_data > maxUARTaddr)
					maxUARTaddr = *UART_data;						// Update the highest address thus far.	
			}	
				
				
			UART_data++;
    		//UART_ptr++;							// TODO: Make sure this doesn't go into another structs space or out of bounds
    		//printf("key %d: %s: ", key_i, key);
    		//printf("0x%lx\n", key_data.u.i);	
        }
        
        // Init UART peripheral registers with their reset values
        uartInit(uc, tab_i);
             
   	}
   	
   	// SANITY CHECK. Check if the min and max addresses for UART match.
   	//printf("minUARTaddr: 0x%x\nmaxUARTaddr: 0x%x\n", minUARTaddr, maxUARTaddr);


	// UART specific callbacks	
	// Callback to handle FW reads before they happen. (Update values in memory before they are read)
	uc_hook_add(uc, &handle1, UC_HOOK_MEM_READ, pre_read_UART, NULL, minUARTaddr, maxUARTaddr);
	// Callback to handle FW reads after they happen. (Update certain registers after reads)
	uc_hook_add(uc, &handle2, UC_HOOK_MEM_READ_AFTER, post_read_UART, NULL, minUARTaddr, maxUARTaddr);	
	// Callback to handle when FW writes to any UART register (DR and CR. SR should change according to CR write.) 
	uc_hook_add(uc, &handle3, UC_HOOK_MEM_WRITE, write_UART, NULL, minUARTaddr, maxUARTaddr);
   	
   		
   	return 0;	  		
}

// Cycle through each UART module and initialize all of their registers.	
void uartInit(uc_engine *uc, int i){

	// TODO: Sanity check these memory locations by reading back later.
	if (uc_mem_write(uc, UART[i]->CR1_ADDR, &UART[i]->CR1_RESET, 4)){
		printf("Failed to Initialize CR1 for UART%d. Quit\n", i);
		exit(1);
	}
	if (uc_mem_write(uc, UART[i]->CR2_ADDR, &UART[i]->CR2_RESET, 4)){
		printf("Failed to Initialize CR2 for UART%d. Quit\n", i);
		exit(1);		
	}
	if (uc_mem_write(uc, UART[i]->CR3_ADDR, &UART[i]->CR3_RESET, 4)){
		printf("Failed to Initialize CR3 for UART%d. Quit\n", i);
		exit(1);	
	}
	if (uc_mem_write(uc, UART[i]->BRR_ADDR, &UART[i]->BRR_RESET, 4)){
		printf("Failed to Initialize BRR for UART%d. Quit\n", i);
		exit(1);	
	}
	if (uc_mem_write(uc, UART[i]->GTPR_ADDR, &UART[i]->GTPR_RESET, 4)){
		printf("Failed to Initialize GTPR for UART%d. Quit\n", i);
		exit(1);	
	}
	if (uc_mem_write(uc, UART[i]->RTOR_ADDR, &UART[i]->RTOR_RESET, 4)){
		printf("Failed to Initialize RTOR for UART%d. Quit\n", i);
		exit(1);	
	}
	if (uc_mem_write(uc, UART[i]->RQR_ADDR, &UART[i]->RQR_RESET, 4)){
		printf("Failed to Initialize RQR for UART%d. Quit\n", i);
		exit(1);	
	}
	if (uc_mem_write(uc, UART[i]->ISR_ADDR, &UART[i]->ISR_RESET, 4)){
		printf("Failed to Initialize ISR for UART%d. Quit\n", i);
		exit(1);	
	}
	if (uc_mem_write(uc, UART[i]->ICR_ADDR, &UART[i]->ICR_RESET, 4)){
		printf("Failed to Initialize ICR for UART%d. Quit\n", i);
		exit(1);	
	}
	if (uc_mem_write(uc, UART[i]->RDR_ADDR, &UART[i]->RDR_RESET, 4)){
		printf("Failed to Initialize RDR for UART%d. Quit\n", i);
		exit(1);	
	}
	if (uc_mem_write(uc, UART[i]->TDR_ADDR, &UART[i]->TDR_RESET, 4)){
		printf("Failed to Initialize TDR for UART%d. Quit\n", i);
		exit(1);	
	}

}
