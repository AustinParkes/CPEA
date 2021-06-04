/*

Compile with:
gcc EmulateUart.c emulatorConfig.c toml.c tester.c -lunicorn -lpthread

*/

#include <unicorn/unicorn.h>
#include <string.h>
#include "emulatorConfig.h"
#include "tester.h"

static void read_mem();			// Callback declaration.
static void readBinFile();		// Read data from binary file

int main(int argc, char **argv, char **envp)
{
	/* Unicorn Initialization */
	uc_engine *uc;
	uc_err err;
 
	uc_hook handle4;   

	char *save_addr;
	int byte;
	int code_size;			// Size of code
	int data_size;			// Size of code data

	char *arm_code;			// ptr to code
	char *arm_data;			// ptr to data
  	
	printf("***Read ARM code and data***\n");

	// Read ARM code
	FILE *f = fopen("SimpleUart.code.bin", "rb");
	if (f == NULL){
		printf("Error opening SimpleUart.code.bin");
		exit(1);	
	}	
	readBinFile(f, &arm_code, &code_size);
	
	// Read ARM data
	FILE *g = fopen("SimpleUart.data.bin", "rb");
	if (g == NULL){
		printf("Error opening SimpleUart.data.bin");
		exit(1);	
	}	
	readBinFile(g, &arm_data, &data_size);
	
	// 
	printf("   - Complete\n\n");
	
	/*** SANITY CHECK ***/
	/*** View binary from file to check if it's correct ***/	
	//read_fbin(arm_code, CODE_ADDR, code_size);			// code
	//read_fbin(arm_data, DATA_ADDR, data_size);			// data

	
	// Create new instance of unicorn engine (Init the emulator)
	err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);	
	if (err != UC_ERR_OK){
		printf("Failed on uc_open() with error returned: %u\n", err);
		exit(1);
	}
	
	// Configure emulator and emulator's peripherals.
	emuConfig(uc, arm_code, arm_data);
	
	/*** SANITY CHECKS ***/
	
	/* View config variables to check if they match emulatorConfig.toml */
	//show_config();
	
	/* Show memory contents of mmio to check if they match reset values.*/
	//show_mmio(uc);
	
	/*** Memory Init ***/	
	// Write code to flash!	
	if (uc_mem_write(uc, CODE_ADDR, arm_code, code_size)){ 
		printf("Failed to write code to memory. Quit\n");
		exit(1);
	}
	free(arm_code);
	arm_code = NULL;
	
	// Write data to flash!
	if (uc_mem_write(uc, DATA_ADDR, arm_data, data_size)){ 
		printf("Failed to write code to memory. Quit\n");
		exit(1);
	}
	free(arm_data);
	arm_data = NULL;	
			
	// Callback to check memory/debug at any code address (specific addresses can be defined in callback)
	uc_hook_add(uc, &handle4, UC_HOOK_CODE, read_mem, NULL, FLASH_ADDR, FLASH_ADDR + FLASH_SIZE);	
					
	// Commit register variables to emulator.
	uc_reg_write(uc, UC_ARM_REG_R0, &r_r0);		// r0
	uc_reg_write(uc, UC_ARM_REG_R1, &r_r1);     // r1
	uc_reg_write(uc, UC_ARM_REG_R2, &r_r2);     // r2
	uc_reg_write(uc, UC_ARM_REG_R3, &r_r3);     // r3
	uc_reg_write(uc, UC_ARM_REG_R4, &r_r4); 	// r4
	uc_reg_write(uc, UC_ARM_REG_R5, &r_r5);		// r5
	uc_reg_write(uc, UC_ARM_REG_R6, &r_r6);		// r6
	uc_reg_write(uc, UC_ARM_REG_R7, &r_r7);		// r7
	uc_reg_write(uc, UC_ARM_REG_R8, &r_r8);   	// r8
	uc_reg_write(uc, UC_ARM_REG_R9, &r_r9); 	// r9
	uc_reg_write(uc, UC_ARM_REG_R10, &r_r10);	// r10
	uc_reg_write(uc, UC_ARM_REG_FP, &FP);		// r11
	uc_reg_write(uc, UC_ARM_REG_R12, &r_r12);	// r12
	uc_reg_write(uc, UC_ARM_REG_SP, &SP);		// r13
	uc_reg_write(uc, UC_ARM_REG_LR, &LR);		// r14

	printf("***Emulate arm code***\n");	
	err=uc_emu_start(uc, START, END, 0, 0);
	if (err){
		printf("Failed on uc_emu_start() with error returned %u: %s\n", err, uc_strerror(err));
		exit(1);
	}
	printf("   - Complete\n\n");
	
	// Free all of the allocated UART structures.
	for (int i=0; i<uart_count; i++){
    	if (UART[i] == NULL){
    		printf("Accessed a peripheral module that shouldn't exist: UART%d\n", i);
    	}
    	free(UART[i]);
    }
    
	// Read end results in registers 
	uc_reg_read(uc, UC_ARM_REG_R0, &r_r0);		// r0
	uc_reg_read(uc, UC_ARM_REG_R1, &r_r1);		// r1
	uc_reg_read(uc, UC_ARM_REG_R2, &r_r2);		// r2
	uc_reg_read(uc, UC_ARM_REG_R3, &r_r3);		// r3
	uc_reg_read(uc, UC_ARM_REG_R4, &r_r4);		// r4
	uc_reg_read(uc, UC_ARM_REG_R5, &r_r5);		// r5
	uc_reg_read(uc, UC_ARM_REG_R6, &r_r6);		// r6
	uc_reg_read(uc, UC_ARM_REG_R7, &r_r7);		// r7	
	uc_reg_read(uc, UC_ARM_REG_R8, &r_r8);		// r8
	uc_reg_read(uc, UC_ARM_REG_R9, &r_r9);		// r9
	uc_reg_read(uc, UC_ARM_REG_R10, &r_r10);	// r10
	uc_reg_read(uc, UC_ARM_REG_FP, &FP);	    // r11	
	uc_reg_read(uc, UC_ARM_REG_R12, &r_r12);	// r12
	uc_reg_read(uc, UC_ARM_REG_SP, &SP);	    // r13
	uc_reg_read(uc, UC_ARM_REG_LR, &LR);	    // r14

	// Show registers R0 - R14
	show_regs();
	
	return 0;
}

// When FW reads from RDR (Before successful read)
void pre_read_UART(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, uint64_t value, void *user_data)
{

	uint32_t Data;  			// For RDR
	uint32_t *UART_ptr;			// Used to iterate through UART modules.
	int uart_i;					// Index for UART module
	UART_handle *UARTx = NULL;	// Points to the UART mmio accessed.
	
	printf("Made it to pre_read_UART callback\n");

	// TODO: Turn into function called findModule
	// FIXME: Need better way to cycle through the addresses. Could break easily in future.	
    // Determine which UART module the accessed address belongs to. 
    /*
    for (uart_i=0; uart_i < uart_count; uart_i++){
    	UART_ptr = (uint32_t *)UART[uart_i];		// Serves as an init and reset for UART_ptr
    	if (!UART_ptr){
    		printf("Error accessing UART%d in pre_read_uartx callback", uart_i);	
    		exit(1);
    	} 	 		
    	*UART_ptr++;								// Skip the base address.
    	
    	// Cycle through each register address and look for a match.
    	for (int addr_cnt=0; addr_cnt < reg_count; addr_cnt++){		// NOTE: 11 is the predetermined # of registers to go through
    		if (*UART_ptr == (uint32_t)address){	
    			UARTx = UART[uart_i];				// Set to the start of the matching UART module
    			break;
    		}
    		else
    			*UART_ptr++;						// No match, move to next UART addr in struct
    	}   	
    	// Leave outer most loop if there is a match.
    	if (UARTx == UART[uart_i])				
    		break;	   		
    }
    */
    
    UARTx = UART[0];
    
    // Produce data for DR read.   
	if	(address == (uint64_t)UARTx->DR_ADDR[DR1]){
    	printf("	Update Data Register\n");
    	Data = 0x6E;		
    	UARTx->DR[DR1] = Data;
    	printf("	DR val: 0x%x\n", Data);		
    	uc_mem_write(uc, UARTx->DR_ADDR[DR1], &UARTx->DR[DR1], 4);  		
    }
    
	else if	(address == (uint64_t)UARTx->DR_ADDR[DR2]){
    	printf("	Update Data Register\n");
    	Data = 0x6E;		
    	UARTx->DR[DR2] = Data;
    	printf("	DR val: 0x%x\n", Data);		
    	uc_mem_write(uc, UARTx->DR_ADDR[DR2], &UARTx->DR[DR2], 4);
    }	
                                 
}

// When FW reads from RDR (After successful read)
void post_read_UART(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, uint64_t value, void *user_data)
{

	int uart_i;					// Index for UART modules
	uint32_t *UART_ptr;			// Points to any given UART module
	UART_handle *UARTx = NULL;	// Points to the UART mmio accessed.

	printf("Made it to post_read_UART callback\n");
	
    /*
    for (uart_i=0; uart_i < uart_count; uart_i++){
    	UART_ptr = (uint32_t *)UART[uart_i];		// Serves as an init and reset for UART_ptr
    	if (!UART_ptr){
    		printf("Error accessing UART%d in pre_read_uartx callback", uart_i);	
    		exit(1);
    	} 	 		
    	*UART_ptr++;								// Skip the base address.
    	
    	// Cycle through each register address and look for a match.
    	for (int addr_cnt=0; addr_cnt < reg_count; addr_cnt++){		// NOTE: 11 is the predetermined # of registers to go through
    		if (*UART_ptr == (uint32_t)address){	
    			UARTx = UART[uart_i];				// Set to the start of the matching UART module
    			break;
    		}
    		else
    			*UART_ptr++;						// No match, move to next UART addr in struct
    	}   	
    	// Leave outer most loop if there is a match.
    	if (UARTx == UART[uart_i])				
    		break;	   		
    }
    */
    
    UARTx = UART[0];
	
	// Clear DR after it's read.
	if	(address == (uint64_t)UARTx->DR_ADDR[DR1]){
    	printf("	Clear DR after read\n");
    	// Data Register should be cleared after it's read
    	UARTx->DR[DR1] = 0;	
    	printf("	DR Val:0x%x\n", UARTx->DR[DR1]);	
    	uc_mem_write(uc, UARTx->DR_ADDR[DR1], &UARTx->DR[DR1], 4);
	  		
    }
	else if	(address == (uint64_t)UARTx->DR_ADDR[DR2]){
    	printf("	Clear DR after read\n");
    	// Data Register should be cleared after it's read
    	UARTx->DR[DR2] = 0;	
    	printf("	DR Val:0x%x\n", UARTx->DR[DR2]);	
    	uc_mem_write(uc, UARTx->DR_ADDR[DR2], &UARTx->DR[DR2], 4);	
	}
                                
}

// When FW writes writes to UART MMIO (Data and Control Registers) 
void write_UART(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, uint64_t value, void *user_data)
{

	/* 
		TODO: Find if we need this or not.
		QEMU will write to memory whether we have this callback or not.
		If SR writes in FW end up overwriting our ideal SR values, then we will need to save our 
		ideal values here and write them back on a pre-read callback.
		
	*/

}

// Read binary data from a file. 
static void readBinFile(FILE *f, char **fdata, int *fsize){

	char *data;								// File Data
	int size;								// Size of file.
	
	// Get size of file and data buffer	
	fseek(f, 0L, SEEK_END);  				// Seek to end of file
	size = ftell(f);    	    			// Get size (in bytes) of code from file
	fseek(f, 0L, SEEK_SET); 				// Reset to start of file
	data = (char *) malloc(1*size);			// Data to be stored. Freed after committing to emulator memory.
	
	// Save size and data buffer outside of function 
	*fsize = size;
	*fdata = data;
	
	// Read byte at a time from binary file
	while (fread(data, 1, size, f) == 1);

	fclose(f);		

}

// Test code at particular execution addresses to read memory and debug
static void read_mem(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{   

    // All for simple polling
	uint32_t r_r3;
	uint32_t var1;
	uint32_t var2;
	
    /*
	if (address == 0x824c){
		printf("Function Entered: Main\n");
	}

	if (address == 0x8264){
		printf("Made it to read_DR()\n");
	}

	// Check if we are branching
    if (address == 0x821c){
    	printf("Function Entered: read_DR()\n");
    }

    if (address == 0x826c){
    	printf("Function Leaving: read_DR()\n");
    }    
 	*/ 
 
}


