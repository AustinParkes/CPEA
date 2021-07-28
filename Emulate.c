/*

Compile with:
gcc -g Emulate.c emulatorConfig.c toml.c tester.c -lunicorn -lpthread

*/

#include <unicorn/unicorn.h>
#include <string.h>
#include "emulatorConfig.h"
#include "tester.h"

static MMIO_handle* findMod();  // Find peripheral module accessed in callback. 
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
	uc_hook svc_handle;         // Hook for handling SVC calls
	

	/* Variables for reading code and data */
	char *save_addr;
	int byte;
	int code_size;			// Size of code
	char *arm_code;			// ptr to code
  	
	printf("***Read ARM Firmware file***\n");

	// Read Firmware File
	FILE *f = fopen("firmware.bin", "rb");
	if (f == NULL){
		printf("Error opening firmware.bin");
		exit(1);	
	}	
	readBinFile(f, &arm_code, &code_size);
		
	printf("   - Complete\n\n");
	
	/*** SANITY CHECK ***/
	/*** View binary from file to check if it's correct ***/	
	//read_fbin(arm_code, CODE_ADDR, code_size);			// code
	//read_fbin(arm_data, DATA_ADDR, data_size);			// data

	
	// Create new instance of unicorn engine for ARM. 
	err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);	
	if (err != UC_ERR_OK){
		printf("Failed on uc_open() with error returned: %u\n", err);
		exit(1);
	}
	
	// Configure emulator memory and peripherals.
	emuConfig(uc, arm_code, code_size);
	
	/*** SANITY CHECKS ***/
	
	/* View config variables to check if they match emulatorConfig.toml */
	show_config();
	
	/* Show memory contents of mmio to check if they match reset values.*/
	//show_mmio(uc);	
	
	// Callback to handle FW reads before they happen.
	uc_hook_add(uc, &handle1, UC_HOOK_MEM_READ, pre_read_MMIO, NULL, minMMIOaddr, maxMMIOaddr);
	
	// Callback to handle FW reads after they happen. 
	uc_hook_add(uc, &handle2, UC_HOOK_MEM_READ_AFTER, post_read_MMIO, NULL, minMMIOaddr, maxMMIOaddr);	
	
	// Callback to handle when FW writes to any MMIO register	
	uc_hook_add(uc, &handle3, UC_HOOK_MEM_WRITE, write_MMIO, NULL, minMMIOaddr, maxMMIOaddr);		
	
	// Callback to check memory/debug at any code address (specific addresses can be defined in callback)
	uc_hook_add(uc, &handle4, UC_HOOK_CODE, read_mem, NULL, CODE_ADDR, CODE_ADDR + CODE_SIZE);	
	
	// Callback to setup entering an SVC handler
	uc_hook_add(uc, &svc_handle, UC_HOOK_INTR, enter_SVC, NULL, CODE_ADDR, CODE_ADDR + CODE_SIZE);
					
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

	printf("\n***Emulate arm code***\n");
	// TODO: Check if this end value is sufficient for code to run forever, until it finishes.
	// NOTE: It's possible to loop this, incase we need to re-execute code sections. 
	//       Can also save CPU context with unicorn API.
	// TODO: See if any other scenario to leave loop: Currently, only leave if there is no error.
	//       Probably scenario for fuzzing, when we want to re-execute certain sections. 
    while(1){
        printf("START:0x%x\n", START);
	    err=uc_emu_start(uc, START, 0xffffffff, 0, 0);
	    if (err){
	        // Check for fetch on non-exectuable memory
	        if (err == UC_ERR_FETCH_PROT){
	            // Check for return from inturrupt handler
	            if ((exc_return & 0xffffffe0) == 0xffffffe0){
	                exc_return = 0;             // Reset EXC_RETURN
	                	              	                 
	                // Check which mode we need to return to. 
	                uc_reg_read(uc, UC_ARM_REG_PC, &PC);
	                if (mode == ARM)
	                    START = PC;                 // Begin execution from where interrupt left off
	                else if (mode == Thumb)
	                    START = PC + 1;    
	                    	                
	            }
	            else{
	                printf("Failed on uc_emu_start() with error returned %u: %s\n", err, uc_strerror(err));
		            exit(1);
	            }	            	        
	        }
	        else{
		        printf("Failed on uc_emu_start() with error returned %u: %s\n", err, uc_strerror(err));
		        exit(1);
		    }
	    }
	}
	printf("   - Complete\n\n");
	
	// Free all of the allocated Peripheral structures.
	for (int i=0; i<mod_count; i++){
    	if (MMIO[i] == NULL)
    		printf("Accessed a peripheral module that shouldn't exist: MMIO%d\n", i);
    	free(MMIO[i]);
    }
    
    // Free all of the allocated SR instances
    for (int i=0; i<inst_i; i++){
        if (SR_INSTANCE == NULL)
            printf("Accessed a SR instance that shouldn't exist: SR%d\n", i);
        free(SR_INSTANCE[i]);
    
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

int pre_read_MMIO(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, uint64_t value, void *user_data)
{

	uint32_t Data;  				// For RDR
	int SR_temp;                    // Temporary SR holding register
	int SR_bit;                     // SR bit location to write to
	int SR_val;                     // Hold SR bit value (1 or 0)
	MMIO_handle *periphx = NULL;	// Points to the peripheral mmio accessed.
	
	printf("Pre Read MMIO callback: 0x%lx\n", address);
	
	// Determine if we are accessing a peripheral we mapped and which.
	periphx = findMod(address, &periphx);
    if (periphx == NULL)
        return -1;
    
	
	// Check if SR instance exists for this module.
	if (periphx->SR_INST == 1){		
		uc_reg_read(uc, UC_ARM_REG_PC, &PC);
		printf("PC: 0x%x\n", PC);	  
	    // Loop SR instances
	    for (int index = 0; index < inst_i; index++){
	 
	        // Check if SR instance matches PC address. Commit to memory.   
	        if (SR_INSTANCE[index]->PROG_ADDR == PC){ 
	            uc_mem_read(uc, address, &SR_temp, 4);
	            SR_bit = SR_INSTANCE[index]->BIT;
	            SR_val = SR_INSTANCE[index]->VAL;
	            if (SR_val == 1)
	                SET_BIT(SR_temp, SR_bit);
	            else
	                CLEAR_BIT(SR_temp, SR_bit);
	                
	            if (uc_mem_write(uc, address, &SR_temp, 4)){
				    printf("Failed to set bit for SR instance %d. Quit\n", index);
				    exit(1);
				}     
	        } 
	    }
	}
    
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
    
    return 0;                            
}

int post_read_MMIO(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, uint64_t value, void *user_data)
{
					
	MMIO_handle *periphx = NULL;	// Points to the peripheral mmio accessed.

	printf("Post Read MMIO callback: 0x%lx\n", address);
	
	// Determine if we are accessing a peripheral we mapped and which.
	periphx = findMod(address, &periphx);
    if (periphx == NULL)
        return -1;	
	
	// Check if SR instance exists for this module
	if (periphx->SR_INST == 1){
	    // Loop SR instances
	}
    	
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
       
    return 0;                            
}

// TODO: May want to update register variables when they are written to atleast.
// When FW writes writes to peripheral MMIO (Data and Control Registers) 
void write_MMIO(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, uint64_t value, void *user_data)
{
    printf("Write MMIO callback: 0x%lx\n", address);
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
	// Freed in flash_init()
	data = (char *)malloc(1*size);			// Data to be stored. Freed after committing to emulator memory.
	
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
    	 	
    	// Get the correct peripheral module. (Does accessed addr match this module?)	 		
		if (address >= MMIO[mod_i]->minAddr && address <= MMIO[mod_i]->maxAddr){
			periphx = MMIO[mod_i];
    		break;
    	}    		
    }

	return periphx;

}

// Callback for entering Exception Handlers
// TODO: Rename this from SVC to something more generic to exceptions
void enter_SVC(uc_engine *uc, uint32_t intno, void *user_data){

    
    // Register IDs for stacking
    uint32_t regID[8] = {UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2 ,UC_ARM_REG_R3,
                         UC_ARM_REG_R12, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR}; 
    // Register variables for stacking
    uint32_t reg[8] = {0, 0, 0, 0, 0, 0, 0, 0};                      

    int reg_i;                      // Register Index

    uint32_t handler_addr;          // Address of SVC handler
    VToffset = 0;                   // Init Vector Table offset to 0   TODO: Place in emulatorConfig.c eventually


    // Disable Interrupt Firing     // TODO: Enable this whenever enabled in NVIC.  
    INTR_EN = 0;

    // SVC exception raised
    if (intno == 2){
        
        // Save Processor Mode (ARM or Thumb) for returning
        uc_reg_read(uc, UC_ARM_REG_CPSR, &CPSR);
        printf("CPSR: 0x%x\n", CPSR);
        if ((CPSR & 0x20) == 0x20)
            mode = Thumb;
        else
            mode = ARM; 

        // Hook for fetch on non-executable memory. (for when PC obtains EXC_RETURN value)       
	    uc_hook_add(uc, &exit_handle, UC_HOOK_MEM_FETCH_PROT, exit_intr, NULL, VENDOR_MEM_ADDR, VENDOR_MEM_ADDR + VENDOR_MEM_SIZE);  
	    
	    // Make room on stack for variables
        uc_reg_read(uc, UC_ARM_REG_SP, &SP);
        SP = SP - 4*8;
        uc_reg_write(uc, UC_ARM_REG_SP, &SP);       
      
        // Push registers to stack in order: r0-r3, r12, LR, PC, CPSR
        for (reg_i=0; reg_i<8; reg_i++){
            uc_reg_read(uc, regID[reg_i], &reg[reg_i]);       
            uc_mem_write(uc, SP, &reg[reg_i], 4);
            SP = SP + 4;
        }
        
        // TODO: See if modifying PC is a problem when emulator isn't stopped. Read that it isn't allowed. 
        // Get SVC Handler address and write to PC
        uc_mem_read(uc, VToffset + 0x2c, &handler_addr, 4);
        printf("SVC Handler: 0x%x\n", handler_addr);     
        uc_reg_write(uc, UC_ARM_REG_PC, &handler_addr);
        
                                         
    }
    else{
        printf("Exception Raised other than SVC: %u", intno);
        exit(1);
    }
    
}


void exit_intr(uc_engine *uc, uint64_t address, uint32_t size, void *user_data){

    uc_reg_read(uc, UC_ARM_REG_PC, &PC);
    uc_reg_read(uc, UC_ARM_REG_LR, &LR);
    printf("exit_intr callback\nPC:0x%x\nLR:0x%x\n", PC, LR);
    
        
    // Register IDs for unstacking
    uint32_t regID[8] = {UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2 ,UC_ARM_REG_R3,
                         UC_ARM_REG_R12, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR};
                                                 
    // Register variables for unstacking
    uint32_t reg[8] = {0, 0, 0, 0, 0, 0, 0, 0};
                                                  
    int reg_i;              // Register Index

    // Undo PC alignment to get back the actual EXC_RETURN value.
    uc_reg_read(uc, UC_ARM_REG_PC, &PC);   
    exc_return = PC + 1;
    
    // Check if PC contains an exception return value (upper 27 bits are 1) 
    if ((exc_return & 0xffffffe0) == 0xffffffe0){
        printf("EXIT INTR, PC:0x%x\n", PC);
        // Pop registers from stack in order: r0-r3, r12, LR, PC, CPSR
        uc_reg_read(uc, UC_ARM_REG_SP, &SP);
        for (reg_i=0; reg_i<8; reg_i++){
            uc_mem_read(uc, SP, &reg[reg_i], 4);
            SP = SP + 4;
            uc_reg_write(uc, regID[reg_i], &reg[reg_i]);
        }
        uc_reg_write(uc, UC_ARM_REG_SP, &SP);       // Update SP
        
        // SANITY CHECK: Check if PC is correct from automatic interrupt stacking/unstacking.                                             
        //uc_reg_read(uc, UC_ARM_REG_PC, &PC);
        //printf("PPCC:0x%x\n", PC);
        

        // Enable Interrupt Firing
        INTR_EN = 1;
       
        // Delete handle, so we aren't searching for end of interrupt handler
        uc_hook_del(uc, exit_handle);
    }
        
        

}

// Test code at particular execution addresses to read memory and debug
static void read_mem(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{  

    printf("Address: 0x%lx\n", address);
                     
}





