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
	uc_hook scs_handle;
	

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
	
	// Callback to setup entering a system exception handler
	uc_hook_add(uc, &svc_handle, UC_HOOK_INTR, enter_intr, NULL, CODE_ADDR, CODE_ADDR + CODE_SIZE);
	
	// Callback for monitoring writes to System Control Space (SCS)
	uc_hook_add(uc, &scs_handle, UC_HOOK_MEM_WRITE, write_SCS, NULL, SCS_ADDR, SCS_END);
	
	// Callback for firing external interrupts
	uc_hook_add(uc, &intr_handle, UC_HOOK_CODE, fire_intr, NULL, CODE_ADDR, CODE_ADDR + CODE_SIZE);				
					
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



// Callback for entering Exception Handlers
void enter_intr(uc_engine *uc, uint32_t intno, void *user_data){

    int IRQ_num;                    // IRQn in vector table. [-16 to n]
    int IRQ_offset;                 // Address of IRQ handler in vector table
    uint32_t handler_addr;          // Address of SVC handler
    TBLOFF = 0;                     // Init Vector Table offset to 0   TODO: Place in emulatorConfig.c eventually

    // Disable Interrupt Firing     // TODO: Enable this whenever enabled in NVIC.  
    INTR_EN = 0;

    // SVC exception raised
    if (intno == 2){

        // Automatic stacking, callback, save mode
        intr_setup(uc);
        
        // TODO: See if modifying PC is a problem when emulator isn't stopped. Read that it isn't allowed. 
        // Get SVC Handler address and write to PC
        uc_mem_read(uc, TBLOFF + 0x2c, &handler_addr, 4);
        printf("SVC Handler: 0x%x\n", handler_addr);     
        uc_reg_write(uc, UC_ARM_REG_PC, &handler_addr);
                                            
    }
    
    // IRQ requested
    else if(intno == 5){
    
        // Automatic stacking, callback, save mode 
        intr_setup(uc);
        
        // Get IRQ handler address and write to PC
        IRQ_num = m_cnt+(32*n_cnt);
        IRQ_offset = (16 + IRQ_num)*4;
        uc_mem_read(uc, TBLOFF + IRQ_offset, &handler_addr, 4);
        printf("IRQ_offset: 0x%x\nIRQ Handler: 0x%x\n", IRQ_offset, handler_addr);     
        uc_reg_write(uc, UC_ARM_REG_PC, &handler_addr);
        /*
        Testing ISERn registers up until this point
        for (int in=0; in<16; in++){        
            printf("ISER%d: 0x%x\n", in, NVIC.ISER[in]); 
        }
        */              
        printf("External Intr Requested\n");
        //exit(1);
    }
    
    else{
        printf("Exception Raised other than SVC: %u", intno);
        exit(1);
    }
    
}

// Automatic stacking, add callback, save processor mode
void intr_setup(uc_engine *uc){

    // TODO: Need to determine when CPSR isn't used and instead the other PSR is used
    // Register IDs for stacking
    uint32_t regID[8] = {UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2 ,UC_ARM_REG_R3,
                         UC_ARM_REG_R12, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR}; 
    // Register variables for stacking
    uint32_t reg[8] = {0, 0, 0, 0, 0, 0, 0, 0};                      

    int reg_i;                      // Register Index
  
    // TODO: May be a bit more to this than JUST checking bit 5 of CPSR
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
      
    // Automatic Stacking. Push registers to stack in order: [(lowest addr) - r0-r3, r12, LR, PC, CPSR - (highest addr)]
    for (reg_i=0; reg_i<8; reg_i++){
        uc_reg_read(uc, regID[reg_i], &reg[reg_i]);       
        uc_mem_write(uc, SP, &reg[reg_i], 4);
        SP = SP + 4;
    } 
    
    // TODO: Note, this is assuming no FP (flaoting point) extension
    // TODO: Auto generating to return to thread mode with MSP as return stack. 
    // Generate EXC_RETURN and store in LR, as old LR is saved on stack   
    exc_return = 0xFFFFFFF9;
    uc_reg_write(uc, UC_ARM_REG_LR, &exc_return);       
}

// Callback to help leave exception handlers
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
    // No exception return value, tried executing non-exectuable portion of memory
    else{
        printf("Tried Executing non-executable portion of memory at: 0x%lx\n", address);
        exit(1);
    }
        
}

// TODO: I'm almost certain this is buggy, so keep testing it.
// Fire enabled interrupts every 1,000 basic blocks in round-robin fashion
void fire_intr(uc_engine *uc, uint64_t address, uint32_t size, void *user_data){

    uint32_t ISERn_addr;        // Computed addr of ISERn
                 
    int n_start;                // Helps determine when no intr are enabled             
    
    bbl_cnt++;                      
    n_start = n_cnt;
    
    // Check if firing mechanism is enabled  
    if (bbl_cnt == 1000){
        bbl_cnt=0; 
 
        // Fire an interrupt 
        if (INTR_EN){      
   
            // Search for the next enabled interrupt to fire.
            // TODO: Check if ISER is value of 0, if so, then no interrupts to fire.
            while (n_cnt<16){ 
                while (m_cnt<32){
                    
                    ISERn_addr = ISER_ADDR + n_cnt*4;
                    uc_mem_read(uc, ISERn_addr, &NVIC.ISER[n_cnt], 4);
                    
                    // Check if intr enabled
                    if (CHECK_BIT(NVIC.ISER[n_cnt], m_cnt)){ 
                                                                                   
                        // Fire off IRQ (IRQ == 5). See cpu.h
                        enter_intr(uc, 5, user_data);                      
                        printf("intr fired off! ... ISER%d: 0x%x\nIntr: %d\n", n_cnt, NVIC.ISER[n_cnt], m_cnt+(32*n_cnt));
                        //exit(1);
                        
                        // Update the ISERn (n) and bit (m) counts
                        if (m_cnt == 31){
                            m_cnt=0;        
                            return;    
                        }
                        else{
                            m_cnt++;
                            return;
                        }                         
                    }
                    
                    // Update the ISERn (n) and bit (m) counts
                    if (m_cnt == 31){
                        m_cnt=0;        
                        break;    
                    }
                    else{
                        m_cnt++;
                        continue;   // Keep Cycling bits
                    } 
                                                
                }
                
                // Update ISERn count
                if (n_cnt == 15){
                    n_cnt=0;  
                }    
                else{
                    n_cnt++;
                    
                    // Check if we've looped the ISER tables without finding enabled interrupt    
                    if (n_cnt == n_start){
                        printf("Looped ISER regs without finding en intr\n");
                        exit(1);
                        break;      // Leave callback                
                    }
                    else
                        continue;   // Keep cycling ISER regs
                }
                                                                                
            }                                          
        }                     
    }

}

// TODO: Need real firmware examples to test these cases to be able to handle them.
void write_SCS(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, uint64_t value, void *user_data)
{
    // TODO TODO TODO: Check if 0s have no effect or not. Will need to bitwise OR results if so.
    
    // Write to Software Trigger Interrupt Register
    if (address == STIR_ADDR){
        printf("STIR Accessed @ 0x%lx\n", address);
        exit(1);                                                                                    
    }
    // System Control Block accessed    
    else if ((address >= SCB_ADDR) && (address <= SCB_END)){
        
        // Determine which SBC register was accessed
        switch(address){
        
            // Interrupt Control Status Register Written to
            case (ICSR_ADDR):

                // Check if NMI set to active
                if (NMIPENDSET){
                    printf("[Unhandled]NMI active\n");
                    exit(1);
                }
                
                // Check if PendSV pending is set or cleared
                if (PENDSVCLR){
                    printf("Remove pending status of PendSV\n");
                    CLEAR_BIT(value, 27);     // Reset PENDSVCLR
                    CLEAR_BIT(value, 28);     // Clear PENDSVSET            
                }                
                else if (PENDSVSET){
                    printf("[Unhandled]PendSV exception pending\n");
                    exit(1);               
                }              
                
                // Check if SysTick pending is set or cleared
                if (PENDSTCLR){
                    printf("Remove pending status of SysTick\n");
                    CLEAR_BIT(value, 25);     // Reset PENDSTCLR
                    CLEAR_BIT(value, 26);     // Clear PENDSTSET
                }                
                else if (PENDSTSET){
                    printf("[Unhandled]SysTick exception pending\n");
                    exit(1);
                }
                
                // TODO: Probably need to clear pending bits when they are no longer pending. Otherwise, could have false positives.        
                // Commit any modifications (if any) to ICSR
                uc_mem_write(uc, ICSR_ADDR, &value, 4); 
                 
                printf("ICRS accessed\n");
                exit(1);    
                break;
                
            case (VTOR_ADDR):
                printf("VTOR accessed and unhandled\n");
                
                // TODO: What happens on non-zero values
                if (value != 0){
                    printf("[Unhandled]VTOR TBLOFF set to non-zero value: 0x%lx\n", value); 
                    
                    // All TBLOFF bits set to 1 (See ARM ref. man. Will find max supported offset value)
                    if ((value & 0xffffff80) == 0xffffff80){
                        printf("[Unhandled]All VTOR TBLOFF bits set to 1");
                        exit(1);
                    }                    
                    exit(1);
                }
                else if (value == 0){
                    TBLOFF = 0;
                }
                
                break;
            
            // TODO: We can place addresses which are byte accessible here ... in if-statements.         
            default:
                printf("[Unhandled]Register in SCB accessed: 0x%lx\n", address);
                //exit(1);
                    
        }
    
    }                
    else if ((address >= NVIC_ADDR) && (address <= NVIC_END)){
        int n;      // Register index [0-15]
        int m;      // Bit location
        
        uint32_t ISERn_addr;        // Computed addr of ISERn
        uint32_t ICERn_addr;        // Computed addr of ICERn
        
        // Write to Interrupt Clear-Enable Register
        if ((address >= ICER_ADDR) && (address <= ICER_END)){
            
            // Compute ICERn
            n = (address - NVIC_ADDR)/4;
            if (n==1){
                printf("ICER1 accessed\n");
                exit(1);
            }
             
            printf("Value: 0x%lx\nISER before: 0x%x\nICER before:0x%x\n", value, NVIC.ISER[n], NVIC.ICER[n]);  
            // 1s disable, 0s have no effect    
            NVIC.ICER[n] &= ~((uint32_t)value);
            
            // ISER also needs to reflect enabled/disabled bits
            NVIC.ISER[n] &= ~((uint32_t)value);
            
            printf("ISER after: 0x%x\nICER after:0x%x\n", NVIC.ISER[n], NVIC.ICER[n]); 
            exit(1);
            
            // Commit these to memory
            uc_mem_write(uc, address, &NVIC.ICER[n], 4);
            
            ISERn_addr = ISER_ADDR + n*4;
            uc_mem_write(uc, ISERn_addr, &NVIC.ISER[n], 4); 
                
        }
        
        // Write to Interrupt Set-Enable Register
        else if ((address >= ISER_ADDR) && (address <= ISER_END)){
                       
            // Compute ISERn
            n = (address - NVIC_ADDR)/4;
            if (n == 1){
                printf("ISER1 accessed\n");
                exit(1);
            }

            // 1s enable, 0s have no effect                                 
            NVIC.ISER[n] |= (uint32_t)value;
            
            // ICER also shows enabled/disabled bits
            NVIC.ICER[n] |= (uint32_t)value;  
        
            // Commit these to memory
            uc_mem_write(uc, address, &NVIC.ISER[n], 4);
            
            ICERn_addr = ICER_ADDR + n*4;
            uc_mem_write(uc, ICERn_addr, &NVIC.ICER[n], 4); 
                   
        }                
        
    }
    

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

// Test code at particular execution addresses to read memory and debug
static void read_mem(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{  

    printf("Address: 0x%lx\n", address);
    if (address == 0x168a){
        uc_reg_read(uc, UC_ARM_REG_LR, &LR);
        printf("LR: 0x%x\n", LR);
        exit(1);
    }
                     
}

