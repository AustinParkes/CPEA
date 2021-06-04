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
void emuConfig(uc_engine *uc, char *arm_code, char *arm_data){
 	
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
    
    // Gather and Store data from emulatorConfig.toml     	
    mmio = parseTOML(root_table);
    
    /***********************************
		General Emulator Configurations.   
    ************************************/
    
    // Memory Map for Emulator
    map_memory(uc);
    
    // Init ARM Registers (includes SP, LR)
    // TODO: See if there is a more legitimate way to init SP.
    // TODO: Init LR to function after main(). 
    reg_init(uc);
    
    /***********************************
		Peripheral Configurations   
    ************************************/
	uartConfig(uc, mmio);
       	     	    	            
    /*** Free Memory for config file ***/
    free(root_table); 
      
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

	// MMIO range for all Cortex-M Devices
	MMIO_ADDR = 0x40000000;
	MMIO_SIZE = 0x20000000;

	// Map Flash region
	if (uc_mem_map(uc, FLASH_ADDR, FLASH_SIZE, UC_PROT_ALL)){
		printf("Failed to map flash region to memory. Quit\n");
		exit(1);
	}
	
	// Map SRAM region (Not executable)
	if (uc_mem_map(uc, SRAM_ADDR, SRAM_SIZE, UC_PROT_READ | UC_PROT_WRITE )){
		printf("Failed to map sram region to memory. Quit\n");
		exit(1);	
	}	
		
	// Map MMIO region 0x40000000 - 0x5FFFFFFF (Not exectuable)
	if (uc_mem_map(uc, MMIO_ADDR, MMIO_SIZE, UC_PROT_READ | UC_PROT_WRITE )){
		printf("Failed to map MMIO region to memory. Quit\n");
		exit(1);
	}
	
	/* 
		SANITY CHECK - See if we can read from a mapped region AND check if that region is filled with 0s 
		INDEED, the mapped memory region is autofilled with 0s.
	*/
	
	/*
	uint32_t var1, var2, var3;
	
	if (uc_mem_read(uc, 0x40000000, &var1, 4))
		printf("Failed to read.\n");
	if (uc_mem_read(uc, 0x40013800, &var2, 4))
		printf("Failed to read.\n");
	if (uc_mem_read(uc, 0x40013810, &var3, 4))
		printf("Failed to read.\n");
	printf("var1:%d\nvar2:%d\nvar3:%d\n", var1, var2, var3);
	*/
	
	
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
	SP = FP;      		// r13	// TODO:	Find better way to init SP and FP
	LR = 0;				// r14	// TODO: 	Set to function after main(). 
	 
}

// Configure UART emulation. 
int uartConfig(uc_engine *uc, toml_table_t* mmio){

	uint32_t base_addr;         // Need base address to check if user entered and offset or absolute address.
	uint32_t data;				// Store key data
	char tab_key[10];			// Stores table names "addr", "reset", & "flags"
	toml_table_t* uartx_tab;
	int tab_i;					// Iterates through TOML peripheral tables
	int SR_i;					// Status Register Index - Keeps track of which SR we are storing to.
	int DR_i;					// Data Register Index - Keeps track of which DR we are storing to.
	int SR_count;				// Number of SR to iterate through.
	int DR_count;
	
	SR_count = 2;				// FIXME: Pull from config file
	DR_count = 2;				// FIXME: Pull from config file
	
	reg_count = 13;				// TODO: Generate from python program or configuration file somehow
								// FIXME: This is not correct register count

	// These keep track of the callback range for UART register accesses.
	minUARTaddr = 0xFFFFFFFF;	// Chose a value that we know is larger than the smallest UART addr
	maxUARTaddr = 0;					
	
 	/*
    	1) Generate UART struct for each module from [memory_map.mmio]
    	2) Traverse to [mmio.uart] and extract register values to UART struct(s)
    	3) Traverse to [mmio.uart_flags] and initialize status registers in mmio.
    */
    
    
    // Get number of UART modules
    toml_datum_t num_uarts = toml_int_in(mmio, "uart_count");
    if (!num_uarts.ok){
    	error("Cannot read mmio.uart_count", "");
    }
    uart_count = (int)num_uarts.u.i;					// Number of UART modules the user specified.
    
    // No UART modules specified.
    // TODO: Check on what user can really set UART count to.  
	if (uart_count <= 0)
		return 0;
	else if (uart_count > MAX_UART - 1 ){
		printf("WARNING: UART count set to %d, but cannot exceed %d. ", uart_count, MAX_UART - 1);
		printf("Setting to 15.");	
		uart_count = 15;	
	}

	// Allocate space for each struct. Freed after emulation is complete. 	
	for (int i=0; i<uart_count; i++){
    	UART[i] = (UART_handle *)malloc(sizeof(UART_handle));
    	if (UART[i] == NULL){
    		printf("UART struct memory not allocated for UART%d\n", i);
    	}
    }
	
    /* 2) Extract UART register config values to UART structs */
    toml_table_t* uart = toml_table_in(mmio, "uart");   // Use mmio pointer from earlier
 	if (!uart){
 		error("missing [mmio.uart]", "");
 	}
 	printf("2\n");
 	// TODO: Add 8-bit/16-bit register mode after full configuration finished.
 	// TODO: Turn these nested for-loops into a function.
 	// Check if UART module exists and how many. "tab_i" keeps track of the number of modules.
 	for (tab_i=0; ; tab_i++){   
 		 	
 		// Check if table exists.    
    	const char* uart_module = toml_key_in(uart, tab_i);
    	if (!uart_module) 
    		break;		
    	
    	// Check if more tables than modules specified.
 		else if (tab_i > (uart_count - 1)){
 			printf("ERROR: %d UART tables, but only %d modules were specified.", tab_i + 1, uart_count);
 			exit(1);
 		}
    	
    	// Get the current UART table ptr from the name
    	toml_table_t* uartx = toml_table_in(uart, uart_module);
    	if (!uartx)
 			error("Failed to get UART table from module %s", uart_module);		
 		
 		// Get ptr to current UART struct data. 
 		//UART_data = (uint32_t *)UART[tab_i];
 		            	
 		//if (!UART_data)
 		//	error("Failed to get pointer from current UART struct", "");
 			
 		
 		// TODO: Get number of registers for UART from python autoscript. (# is hardcoded rn)
    	// Fill UART struct with current UART module configuration values   
    	for (int key_i=0; ; key_i++){
    		const char* key = toml_key_in(uartx, key_i);
    		
    		// Check if key, then check if we reached the SR flags
    		if (!key) 
    			break;
    		printf("key_i: %d\nkey: %s\n", key_i, key); 
    		// Set the table identifier that our data is beneath.	
    		if (!strcmp(key, "addr")){
    			strcpy(tab_key, key);
				uartx_tab = toml_table_in(uartx, tab_key);
    			SR_i = 0;
    			DR_i = 0;
    			continue;						// Skip to next iteration to get data
    		}	
    		else if (!strcmp(key, "reset")){
    			strcpy(tab_key, key);
    			uartx_tab = toml_table_in(uartx, tab_key);
    			SR_i = 0;
    			DR_i = 0;	
    			continue;	
    		}		
    		else if (!strcmp(key, "flags"))
    			break;
    					
    		// Get data from the current key
    		toml_datum_t key_data = toml_int_in(uartx_tab, key);
    		if (!key_data.ok)
    			error("Cannot read key data", "");
    		data = (uint32_t)key_data.u.i;
    		printf("key_i: %d\n", key_i);   		
    		// Store base addr first.
			if (key_i == 1){
    			base_addr = data;				
    			UART[tab_i]->BASE_ADDR = base_addr;				 
    		}
    		
    		// Store addr and reset values    		
    		else{ 
    			printf("%s\n", tab_key);	    			
				if (!strcmp(tab_key, "addr")){
					// Check if user entered offset and convert to absolute address.
					if (data < base_addr)
						data = data + base_addr;
					printf("data: %d", data);
					// TODO: May store min,max addr for each module.
					// Keep track of lowest and highest addr.
					if (data < minUARTaddr)
						minUARTaddr = data;
					else if (data > maxUARTaddr)
						maxUARTaddr = data;
					
					// Store addr data	
					if (SR_i < SR_count){
						UART[tab_i]->SR_ADDR[SR_i] = data;
						SR_i++;	
					}
					else{
						UART[tab_i]->DR_ADDR[DR_i] = data;
						DR_i++;
					} 
				}
								
				// Reset Values
				else if(!strcmp(tab_key, "reset")){
					if (SR_i < SR_count){
						UART[tab_i]->SR_RESET[SR_i] = data;
						SR_i++;	
					}
					else{
						UART[tab_i]->DR_RESET[DR_i] = data;
						DR_i++;
					}
									
				// Table that shouldn't exist.	 				
				}
				else
					error("Non-existent table accessed: %s", tab_key);
					
    		}			
			
        }     
          
        // Init UART peripheral registers with their reset values
        uartInit(uc, tab_i);
        
        /* 3) Set Status Registers' ideal flag values based on config */        
        toml_table_t* flags = toml_table_in(uartx, "flags");   
 		if (!flags){
 			error("missing [mmio.uart.%d.flags]", tab_i);
 		}	
        
        setFlags(uc, flags);	         
   	}
   	
   	// SANITY CHECK. Check if the min and max addresses for UART match.
   	printf("minUARTaddr: 0x%x\nmaxUARTaddr: 0x%x\n", minUARTaddr, maxUARTaddr);
   	

	// UART specific callbacks
		
	// Callback to handle FW reads before they happen. (Update values in memory before they are read)
	uc_hook_add(uc, &handle1, UC_HOOK_MEM_READ, pre_read_UART, NULL, minUARTaddr, maxUARTaddr);
	// Callback to handle FW reads after they happen. (Update certain registers after reads)
	uc_hook_add(uc, &handle2, UC_HOOK_MEM_READ_AFTER, post_read_UART, NULL, minUARTaddr, maxUARTaddr);	
	// Callback to handle when FW writes to any UART register (DR and CR. SR should change according to CR write.) 
	uc_hook_add(uc, &handle3, UC_HOOK_MEM_WRITE, write_UART, NULL, minUARTaddr, maxUARTaddr);
   	
   		
   	return 0;	  		
}

/* 
	TODO: Better way to check if a register is used by emulator?
		  Currently checking if it's address falls within the expected range.

*/


// Cycle through each UART module and initialize mmio registers.
// (Only initializes mmio registers that are used.)	
void uartInit(uc_engine *uc, int i){

	// Check to see if the register's address falls into the expected range. AKA is register used or not?	
	if ((UART[i]->SR_ADDR[SR1] >= minUARTaddr) && (UART[i]->SR_ADDR[SR1] <= maxUARTaddr)){
		if (uc_mem_write(uc, UART[i]->SR_ADDR[SR1], &UART[i]->SR_RESET[SR1], 4)){
			printf("Failed to Initialize ISR for UART%d. Quit\n", i);
			exit(1);	
		}
	}
	if ((UART[i]->SR_ADDR[SR2] >= minUARTaddr) && (UART[i]->SR_ADDR[SR2] <= maxUARTaddr)){
		if (uc_mem_write(uc, UART[i]->SR_ADDR[SR2], &UART[i]->SR_RESET[SR2], 4)){
			printf("Failed to Initialize ISR for UART%d. Quit\n", i);
			exit(1);	
		}
	}
	
	if ((UART[i]->DR_ADDR[DR1] >= minUARTaddr) && (UART[i]->DR_ADDR[DR1] <= maxUARTaddr)){
		if (uc_mem_write(uc, UART[i]->DR_ADDR[DR1], &UART[i]->DR_RESET[DR1], 4)){
			printf("Failed to Initialize RDR for UART%d. Quit\n", i);
			exit(1);	
		}
	}
	
	if ((UART[i]->DR_ADDR[DR2] >= minUARTaddr) && (UART[i]->DR_ADDR[DR2] <= maxUARTaddr)){
		if (uc_mem_write(uc, UART[i]->DR_ADDR[DR2], &UART[i]->DR_RESET[DR2], 4)){
			printf("Failed to Initialize TDR for UART%d. Quit\n", i);
			exit(1);	
		}
	}
}

void setFlags(uc_engine *uc, toml_table_t* flag_tab){
	int i;						// UART module index
	int tab_i;					// Table Index
	int SR_i;					// String Index for Status Registers
	int flag_bit;				// Bit location that flag belongs to
	const char* flag_name;		// Name of current flag
	const char* flag_reg;		// Name of register flag belongs to
	toml_table_t* flag_ptr;		// ptr to flag table
	toml_datum_t flag_key;		// Holds a key value from flag table
	
	enum letter_case {up_case, low_case};
	
	// TODO: Only doing up to 8 str for now. Find better number in future	
	char reg_name[2][8][4] = {
	{{"SR1"},{"SR2"},{"SR3"},{"SR4"},{"SR5"},{"SR6"},{"SR7"},{"SR8"}},
	{{"sr1"},{"sr2"},{"sr3"},{"sr4"},{"sr5"},{"sr6"},{"sr7"},{"sr8"}}
	};
	
	for (tab_i = 0; ;tab_i++){
	
 		// Check if table exists and leave when we finish.    
    	flag_name = toml_key_in(flag_tab, tab_i);
    	if (!flag_name) 
    		break;
    					
		printf("%s\n", flag_name);
		
			
		// Get the current Flag table ptr from its name
    	flag_ptr = toml_table_in(flag_tab, flag_name);
    	if (!flag_ptr)
 			error("Failed to get Flag table: %s", flag_name);
 			
 		// Get the register the flag belongs to 
    	flag_key = toml_string_in(flag_ptr, "reg");
    	if (!flag_key.ok)
    		error("Failed to get flag register from: %s", flag_name);
    	flag_reg = flag_key.u.s;
	
 		// Get the bit location the flag belongs to		
		flag_key = toml_int_in(flag_ptr, "bit");
    	if (!flag_key.ok)
    		error("Failed to get flag bit location from: %s", flag_name);	
    	flag_bit = flag_key.u.i;
    	
    	/* SANITY CHECK - Check register and bit */
    	//printf("reg: %s\nbit: %d\n",flag_reg, flag_bit);
    	
    	/* 
    		Write current flag to the appropriate SR and bit location
    		for all UART modules
    	*/
    	/*
    	printf("str_count: %ld", sizeof(reg_name[0])/sizeof(reg_name[0][0]));
    	for (SR_i=0; SR_i<8; SR_i++){
    		printf("reg_name: %s\n", reg_name[up_case][SR_i]);		
    		if (!strcmp(flag_reg, reg_name[up_case][SR_i]) || !strcmp(flag_reg, reg_name[low_case][SR_i])){
    			for (i=0; i<uart_count; i++){
    				SET_BIT(UART[i]->SR[SR_i], flag_bit);	
    				if (uc_mem_write(uc, UART[i]->SR_ADDR[SR_i], &UART[i]->SR[SR_i], 4)){
						printf("Failed to set bit for SR1 at UART%d. Quit\n", i);
						exit(1);
					}
    			} 			
    		}
    		break;   // Break if match found.	
    	}
    	*/
    	// Check for other possible cases
    	//if (!strcmp(flag_reg, "reg"))
    		//;
    	//else
    	//	error("Please give \"reg\" name in formats SRx or srx. You gave: ", flag_reg, "");
    	
    	if (!strcmp(flag_reg, "SR1") || !strcmp(flag_reg, "sr1")){
    		for (i=0; i<uart_count; i++){
    			SET_BIT(UART[i]->SR[SR1], flag_bit);
    			if (uc_mem_write(uc, UART[i]->SR_ADDR[SR1], &UART[i]->SR[SR1], 4)){
					printf("Failed to set bit for SR2 at UART%d. Quit\n", i);
					exit(1);
				} 			
    		}
    	}  	
    	else if (!strcmp(flag_reg, "SR2") || !strcmp(flag_reg, "sr2")){
    		for (i=0; i<uart_count; i++){
    			SET_BIT(UART[i]->SR[SR2], flag_bit);
    			if (uc_mem_write(uc, UART[i]->SR_ADDR[SR2], &UART[i]->SR[SR2], 4)){
					printf("Failed to set bit for SR2 at UART%d. Quit\n", i);
					exit(1);
				}    			
    		}
    	}
    	
    	
    	/*
    	else if (!strcmp(flag_reg, "SR3") || !strcmp(flag_reg, "sr3")){
    		for (uart_i=0; uart_i<uart_count; uart_i++){
    			SET_BIT(UART[uart_i]->SR3, flag_bit);
    		}
    	}
    	else if (!strcmp(flag_reg, "SR4") || !strcmp(flag_reg, "sr4")){
    		for (uart_i=0; uart_i<uart_count; uart_i++){
    			SET_BIT(UART[uart_i]->SR4, flag_bit);
    		}
    	}  
    	*/ 	    	    	
    	else if (!strcmp(flag_reg, "reg"))
    		;
    	else
    		error("Please give \"reg\" name in formats SRx or srx. You gave: ", flag_reg, "");
    	

	}	

}

void error(const char *msg, const char* msg1, const char* msg2)
{
	fprintf(stderr, "ERROR: %s%s%s\n", msg, msg1?msg1:"", msg2?msg2:"");
	exit(1);
}
