/*

Compile with:
gcc EmulateUart.c emulatorConfig.c toml.c tester.c -lunicorn -lpthread

*/

#include <unicorn/unicorn.h>
#include <string.h>
#include "emulatorConfig.h"
#include "tester.h"

static MMIO_handle* findMod();
static void read_mem();			// Callback gdeclaration.
static void readBinFile();		// Read data from binary file

int main(int argc, char **argv, char **envp)
{
	/* Unicorn Initialization */
	uc_engine *uc;
	uc_err err;
	
	uc_hook handle1;			// Used by uc_hook_add to give to uc_hook_del() API
	uc_hook handle2;
	uc_hook handle3; 
	uc_hook handle4;   

	/* Variables for reading code and data */
	char *save_addr;
	int byte;
	int code_size;			// Size of code
	int data_size;			// Size of code data

	char *arm_code;			// ptr to code
	char *arm_data;			// ptr to data
  	
	printf("***Read ARM code and data***\n");

	

	// Read ARM code
	FILE *f = fopen("firmware.code.bin", "rb");
	if (f == NULL){
		printf("Error opening firmware.code.bin");
		exit(1);	
	}	
	readBinFile(f, &arm_code, &code_size);
	
	// Read ARM data
	FILE *g = fopen("firmware.data.bin", "rb");
	if (g == NULL){
		printf("Error opening firmware.data.bin");
		exit(1);	
	}	
	readBinFile(g, &arm_data, &data_size);
	
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
	
	// Configure emulator memory and peripherals.
	emuConfig(uc, arm_code, arm_data, code_size, data_size);
	
	/*** SANITY CHECKS ***/
	
	/* View config variables to check if they match emulatorConfig.toml */
	show_config();
	
	/* Show memory contents of mmio to check if they match reset values.*/
	//show_mmio(uc);	
	
	// Callback to handle FW reads before they happen.
	uc_hook_add(uc, &handle1, UC_HOOK_MEM_READ, pre_read_MMIO, NULL, minPeriphaddr, maxPeriphaddr);
	
	// Callback to handle FW reads after they happen. 
	uc_hook_add(uc, &handle2, UC_HOOK_MEM_READ_AFTER, post_read_MMIO, NULL, minPeriphaddr, maxPeriphaddr);	
	
	// Callback to handle when FW writes to any MMIO register	
	uc_hook_add(uc, &handle3, UC_HOOK_MEM_WRITE, write_MMIO, NULL, minPeriphaddr, maxPeriphaddr);		
	
	// Callback to check memory/debug at any code address (specific addresses can be defined in callback)
	uc_hook_add(uc, &handle4, UC_HOOK_CODE, read_mem, NULL, CODE_ADDR, CODE_ADDR + CODE_SIZE);	
					
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
	
	// Free all of the allocated Peripheral structures.
	for (int i=0; i<mod_count; i++){
    	if (MMIO[i] == NULL){
    		printf("Accessed a peripheral module that shouldn't exist: MMIO%d\n", i);
    	}
    	free(MMIO[i]);
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

void pre_read_MMIO(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, uint64_t value, void *user_data)
{

	uint32_t Data;  				// For RDR
	MMIO_handle *periphx = NULL;	// Points to the peripheral mmio accessed.
	
	printf("Pre Read MMIO callback\n");
	
	// Determine which MMIO module the accessed address belongs to.
	periphx = findMod(address, &periphx);

   
    // Produce data for DR read.   
	if	(address == (uint64_t)periphx->DR_ADDR[DR1]){
    	printf("	Update Data Register\n");
    	Data = 0x6E;		
    	periphx->DR[DR1] = Data;
    	printf("	DR val: 0x%x\n", Data);		
    	uc_mem_write(uc, periphx->DR_ADDR[DR1], &periphx->DR[DR1], 4);  		
    }
    
	else if	(address == (uint64_t)periphx->DR_ADDR[DR2]){
    	printf("	Update Data Register\n");
    	Data = 0x6E;		
    	periphx->DR[DR2] = Data;
    	printf("	DR val: 0x%x\n", Data);		
    	uc_mem_write(uc, periphx->DR_ADDR[DR2], &periphx->DR[DR2], 4);
    }	
                                 
}

void post_read_MMIO(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, uint64_t value, void *user_data)
{
					
	MMIO_handle *periphx = NULL;	// Points to the peripheral mmio accessed.

	printf("Post Read MMIO callback\n");
	periphx = findMod(address, &periphx);
	
	// Clear DR after it's read.
	if	(address == (uint64_t)periphx->DR_ADDR[DR1]){
    	printf("	Clear DR after read\n");
    	// Data Register should be cleared after it's read
    	periphx->DR[DR1] = 0;	
    	printf("	DR Val:0x%x\n", periphx->DR[DR1]);	
    	uc_mem_write(uc, periphx->DR_ADDR[DR1], &periphx->DR[DR1], 4);
	  		
    }
	else if	(address == (uint64_t)periphx->DR_ADDR[DR2]){
    	printf("	Clear DR after read\n");
    	// Data Register should be cleared after it's read
    	periphx->DR[DR2] = 0;	
    	printf("	DR Val:0x%x\n", periphx->DR[DR2]);	
    	uc_mem_write(uc, periphx->DR_ADDR[DR2], &periphx->DR[DR2], 4);	
	}
                                
}

// When FW writes writes to peripheral MMIO (Data and Control Registers) 
void write_MMIO(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, uint64_t value, void *user_data)
{

	/* 
		TODO: Find if we need this or not.
		QEMU will write to memory whether we have this callback or not.
		If SR writes in FW end up overwriting our ideal SR values, then we will need to save our 
		ideal values here and write them back on a pre-read callback.
		
	*/

}

// Read binary data from a file for fsize bytes
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

static MMIO_handle* findMod(uint64_t address, MMIO_handle** periph){

	int mod_i;		// Index for peripheral module
	MMIO_handle *periphx = *periph;
	
    // Determine which MMIO module the accessed address belongs to.     
    for (mod_i=0; mod_i < mod_count; mod_i++){
    
    	if (!MMIO[mod_i]){
    		printf("Error accessing MMIO%d in pre_read_MMIO callback", mod_i);	
    		exit(1);
    	} 
    		 	
    	// Get the correct peripheral module	 		
		if (address >= MMIO[mod_i]->minAddr && address <= MMIO[mod_i]->maxAddr){
			periphx = MMIO[mod_i];
    		break;
    	}
  		
    }

	return periphx;

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


