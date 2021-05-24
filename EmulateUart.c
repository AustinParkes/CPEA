/*

Compile with:
gcc EmulateUart.c emulatorConfig.c toml.c tester.c -lunicorn -lpthread

*/

#include <unicorn/unicorn.h>
#include <string.h>
#include "emulatorConfig.h"
#include "tester.h"

/* UART Emulation for stm32l4xx MCUs for ARM Cortex-M */


/*** UART Bit Configuration Checks ***/
/*
3)	In future, the user will just need to specify what bit needs to be 
    checked. The register that it's checked for is already pre-configured from 
    step 2) and this check will already be enabled for that register and disabled
    for the other registers.
    
    For user's ease, user can configure only the bits that need to be checked for certain flags
    such as CHECK_STOPBITS ... instead of configuring the same bits for CHECK_STOPBITS .5, 1, 1.5, 2,
    user can set the bits for a Master CHECK_STOPBITS that will check those bits in each individual check.
    After this, user can move on to step 4) and configure the bits that should be set in 
    status registers according to the configuration set.
*/
// Check if kth bit is set or not in register (Check if UART enabled(1) / disabled(0)) 
#define CHECK_ENABLE(reg, k)	(reg & (1<<k)) 

// Check if any 2 bits are both 0. (Check if UART 8-N-1)
#define CHECK_WORDLENGTH8(reg,k1,k2)  (~reg & (1<<k1)) && (~reg & (1<<k2))

// Check among 2 bits if 1 is set and the other is not set. (check if UART 7-N-1)
#define CHECK_WORDLENGTH7(reg, k1Set, k2Not)  (reg & (1<<k1Set)) && (~reg & (1<<k2Not))

// Check if kth bit is set or not in register (Check if parity is enabled (1) / disabled (0))
#define CHECK_PARITY_EN(reg, k)	(reg & (1<<k)) 

// Check if any 2 bits are both 0 (Check if 1 stop bit)
#define CHECK_STOPBITS1(reg,k1,k2)  (~reg & (1<<k1)) && (~reg & (1<<k2))

// Check if kth bit is set or not in register (Check if oversample8 (enabled (1)) / oversample16 (disabled(0)) )
#define CHECK_OVERSAMPLE(reg, k)	(reg & (1<<k)) 

// Check if kth bit is set or not in register (Check if transmitter enabled (1) / disabled (0))
#define CHECK_TX_ENABLE(reg, k)	(reg & (1<<k)) 

// Check if kth bit is set or not in register (Check if receiver enabled (1) / disabled (0))
#define CHECK_RX_ENABLE(reg, k)	(reg & (1<<k))

// Check if kth bit is set or not in register (Check if receiver enabled (1) / disabled (0))
#define CHECK_TCCF(reg, k)	(reg & (1<<k))

/*** UART Status Register Sets/Clears ***/

// Set kth bit in register (Sets the Transmit enable Acknowledge flag if transmitter is enabled)
#define SET_TEACK(reg, k)	(reg |= (1<<k))

// Clear kth bit in register (Clears the Transmit enable Acknowledge flag if transmitter is disabled)
#define CLEAR_TEACK(reg, k)	(reg &= ~(1<<k))			

// Set kth bit in register (Sets the Receive enable Acknowledge flag if receiver is enabled)
#define SET_REACK(reg, k)	(reg |= (1<<k))

// Clear kth bit in register (Clears the Receive enable Acknowledge flag if receiver is disabled)
#define CLEAR_REACK(reg, k)	(reg &= ~(1<<k))

// Set kth bit in register (Sets the Read Data Register Not Empty flag)
#define SET_RXNE(reg, k)	(reg |= (1<<k))

// Clear kth bit in register (Clears the Read Data Register Not Empty flag)
#define CLEAR_RXNE(reg, k)	(reg &= ~(1<<k))

// Set kth bit in register (Sets the Transmit Data Register Empty)
#define SET_TXE(reg, k)	(reg |= (1<<k))

// Clear kth bit in register (Clears the Transmit Data Register Empty)
#define CLEAR_TXE(reg, k)	(reg &= ~(1<<k))

// Set kth bit in register (Sets Transmission Complete Flag)
#define SET_TC(reg, k)	(reg |= (1<<k))

// Clear kth bit in register (Clears the Transmission Complete Flag)
#define CLEAR_TC(reg, k)	(reg &= ~(1<<k))


/*** UART Hardware Flags and Masks***/
/* These flags aren't actually available in UART registers, so we declare them here */

// Mask data to be 7, 8, 9 bits
uint8_t Data_Mask = 0xFF;	  	// 8 bits default


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
  	
	printf("Read ARM code and data\n");

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
	printf("   - Complete\n");
	
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

	printf("Emulate arm code\n");	
	err=uc_emu_start(uc, START, END, 0, 0);
	if (err){
		printf("Failed on uc_emu_start() with error returned %u: %s\n", err, uc_strerror(err));
		exit(1);
	}
	printf("   - Complete\n");
	
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

	// Show registers R0 - R13
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
    
    // TODO: Make more generic for OTHER Peripherals.
    // TODO: Add some checks to make sure that pointer isn't going out of bounds
    // TODO: Check for general correctness in semantics
    
    // Determine which UART module the accessed address belongs to. 
    for (uart_i=0; uart_i < uart_count; uart_i++){
    	UART_ptr = (uint32_t *)UART[uart_i];		// Serves as an init and reset for UART_ptr
    	if (!UART_ptr){
    		printf("Error accessing UART%d in pre_read_uartx callback", uart_i);	
    		exit(1);
    	} 	 		
    	*UART_ptr++;								// Skip the base address.
    	
    	// Cycle through each register address and look for a match.
    	for (int addr_cnt=0; addr_cnt < 11; addr_cnt++){		// NOTE: 11 is the predetermined # of registers to go through
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
    

    // TODO, in future, may not need to even check all of these registers.
    // Determine which UART register is going to be accessed.
	if	(address == (uint64_t)UARTx->CR1_ADDR)
		;
	else if	(address == (uint64_t)UARTx->CR2_ADDR)
		;
	else if	(address == (uint64_t)UARTx->CR3_ADDR)
		;
	else if	(address == (uint64_t)UARTx->BRR_ADDR)
		;
	else if	(address == (uint64_t)UARTx->GTPR_ADDR)
		;
	else if	(address == (uint64_t)UARTx->RTOR_ADDR)
		;
	else if	(address == (uint64_t)UARTx->RQR_ADDR)
		;
	else if	(address == (uint64_t)UARTx->ISR_ADDR){
    		printf("	Update ISR\n");
    
    	/*
    	bits 25, 7, & 6 are set by default in ISR.
    	25 is undetermined atm
    	7 & 6 never change, since there is no logical reason to ever change them
    	*/
    	// Commit the current ISR value to memory before fw reads it
    	
    	uc_mem_write(uc, UARTx->ISR_ADDR, &UARTx->ISR, 4);
    }
	else if	(address == (uint64_t)UARTx->ICR_ADDR)
		;
	else if	(address == (uint64_t)UARTx->RDR_ADDR){
    	printf("	Update Data Register\n") ;
    	Data = 0xEE;		
    	// Mask should be 7 bit in this test (Data == 0x6E)
    	Data &= Data_Mask;		// Mask according to 7, 8, 9 bit data 
    	UARTx->RDR = Data;
    	printf("	DR val: 0x%x\n", Data);		
    	uc_mem_write(uc, UARTx->RDR_ADDR, &UARTx->RDR, 4);
    	// Data is loaded into DR at this point, so RXNE == 1
    	SET_RXNE(UARTx->ISR, 5);   // Set bit 5 (RXNE)    		
    }
	else if	(address == (uint64_t)UARTx->TDR_ADDR)
		;
	else{
		printf("Address does not match any UART%d register addresses.\n", uart_i);
		exit(1);
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
	
    for (uart_i=0; uart_i < uart_count; uart_i++){
    	UART_ptr = (uint32_t *)UART[uart_i];		// Serves as an init and reset for UART_ptr
    	if (!UART_ptr){
    		printf("Error accessing UART%d in pre_read_uartx callback", uart_i);	
    		exit(1);
    	} 	 		
    	*UART_ptr++;								// Skip the base address.
    	
    	// Cycle through each register address and look for a match.
    	for (int addr_cnt=0; addr_cnt < 11; addr_cnt++){		// NOTE: 11 is the predetermined # of registers to go through
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

    // TODO, in future, may not need to even check all of these registers.
    // Determine which UART register is going to be accessed.
	if (address == (uint64_t)UARTx->CR1_ADDR)
		;
	else if	(address == (uint64_t)UARTx->CR2_ADDR)
		;
	else if	(address == (uint64_t)UARTx->CR3_ADDR)
		;
	else if	(address == (uint64_t)UARTx->BRR_ADDR)
		;
	else if	(address == (uint64_t)UARTx->GTPR_ADDR)
		;
	else if	(address == (uint64_t)UARTx->RTOR_ADDR)
		;
	else if	(address == (uint64_t)UARTx->RQR_ADDR)
		;
	else if	(address == (uint64_t)UARTx->ISR_ADDR)
		;
	else if	(address == (uint64_t)UARTx->ICR_ADDR)
		;
	else if	(address == (uint64_t)UARTx->RDR_ADDR){
    	printf("	Clear DR after read\n");
    	// Data Register should be cleared after it's read
    	UARTx->RDR = 0;	
    	printf("	DR Val:0x%x\n", UARTx->RDR);	
    	uc_mem_write(uc, UARTx->RDR_ADDR, &UARTx->RDR, 4);
    	// Data has been read already, so RXNE == 0
    	CLEAR_RXNE(UARTx->ISR, 5);   // Clear bit 5 (RXNE) 	  		
    }
	else if	(address == (uint64_t)UARTx->TDR_ADDR)
		;
	else{
		printf("Address does not match and of UART%d register addresses.\n", uart_i);
		exit(1);
    }
                                
}

// When FW writes writes to UART MMIO (Data and Control Registers) 
void write_UART(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, uint64_t value, void *user_data)
{


	int uart_i;					// Index for UART modules
	uint32_t *UART_ptr;			// Points to any given UART module
	UART_handle *UARTx = NULL;	// Points to the UART mmio accessed.

	printf("Made it to write_UART callback\n\n");
	
    for (uart_i=0; uart_i < uart_count; uart_i++){
    	UART_ptr = (uint32_t *)UART[uart_i];		// Serves as an init and reset for UART_ptr
    	if (!UART_ptr){
    		printf("Error accessing UART%d in pre_read_uartx callback", uart_i);	
    		exit(1);
    	} 	 		
    	*UART_ptr++;								// Skip the base address.
    	
    	// Cycle through each register address and look for a match.
    	for (int addr_cnt=0; addr_cnt < 11; addr_cnt++){		// NOTE: 11 is the predetermined # of registers to go through
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
	
	/*	
	    Certain Emulation Exceptions:
		1) If UART is enabled, certain bits in multiple registers cannot be written to.
		   It's assumed that the FW disabled/enables UART accordingly and that the FW has
		   previously been ran on an actual device. Therefore, enable/disable checks are emitted 
		   from the emulator.
	*/

	bool terminate = false;			 		// Terminate register checks/writes when true
	uint8_t check_flag;					// Change state of switch-case statements for configuration registers
	
	if (address == (uint64_t)UARTx->CR1_ADDR){
		printf("Configure CR1\n");
		/*
			In future, will likely revert to if-statements in the future 
			to check what configurations the user disabled/enabled. 
				  Disabled configs will be zero.   (therefore not executed)
				  Enabled configs will be non-zero (therefore executed)
		*/			
		UARTx->CR1 = (uint32_t)value;    // Save value written to memory in CR1
		check_flag = ENABLE;   // Check if UART enabled first
		while (!terminate){
			switch (check_flag){

				case (ENABLE) :
					// Check if bit 0 of CR1 is set
					if (CHECK_ENABLE(UARTx->CR1, 0)){
						printf("	Enable: UART%d Enabled\n", uart_i);
						UART_enable = true;            // May not need to check if UART is enabled/disabled anymore					
						check_flag = TxENABLE;   		 // Skip all cases that require disabled UART
					}
					// UART Disabled, so reset ISR
					else{
						printf("	Enable: UART%d Disabled\n", uart_i);
						UART_enable = false;			// May not need to check if UART1 is enabled/disabled anymore
						UARTx->ISR = UARTx->ISR_RESET;
						uc_mem_write(uc, UARTx->ISR_ADDR, &UARTx->ISR, 4);   // Update status register	
						check_flag = WORDLENGTH;
					}
					break;
					
				/*
					In future, need to check for 9 bit configuration as well
				*/
				// Only can be configured when UART Disabled
				case (WORDLENGTH) :  
					// Check if both bits are 0.
					if (CHECK_WORDLENGTH8(UARTx->CR1, 28, 12)){
						printf("	WordLength: 8 Bit Data\n");
						Data_Mask = 0xFF;	// 8 bit data (somewhat redundant )
					}
					// Check if bit 28 is 1 and bit 12 is 0
					else if (CHECK_WORDLENGTH7(UARTx->CR1, 28, 12)){
						printf("	WordLength: 7 Bit Data\n");
						Data_Mask = 0x7F;	// 7 bit data
					}
						
				// Fall-Through
				/*
					In some cases fw may be able to red parity bit
				*/
				// Only can be configured when UART Disabled
				case (PARITY_ENABLE) :
					if (CHECK_PARITY_EN(UARTx->CR1, 10)){
						printf("	ParityEnable: Enabled\n");  	// Let us know it was set 
					}
					else if (!CHECK_PARITY_EN(UARTx->CR1, 10)){
						printf("	ParityEnable: Disabled\n");  	// Let us know it wasn't set (Expected Result)
					}
					else{
						printf("	Parity set incorrectly (Not expected from fw)\n");
					}
						
				// Fall-Through
				// Only can be configured when UART Disabled
				case (OVERSAMPLE) :
					
					if (CHECK_OVERSAMPLE(UARTx->CR1, 15)){
						printf("	Oversample: Oversample 8 Set\n");
					}
					else if (!CHECK_OVERSAMPLE(UARTx->CR1, 15)){
						printf("	Oversample: Oversample 16 Set\n");
					}
					else{
						printf("	Oversample set incorrectly (Not expected from fw)\n");
					}
						
			    // Fall-Through
			    case (TxENABLE) :
			    	if (CHECK_TX_ENABLE(UARTx->CR1, 3)){
			    		printf("	TxEnable: Enabled\n");
			    		SET_TEACK(UARTx->ISR, 21);   	// Set bit 21 of ISR (TEACK)
			    	}
			    	else if (!CHECK_TX_ENABLE(UARTx->CR1, 3)){
			    		printf("	TxEnable: Disabled\n");
			    		CLEAR_TEACK(UARTx->ISR, 21);   	// Clear bit 21 of ISR (TEACK)
			    	}
					else {
						printf("	Tx Enable set incorrectly (Not expected from fw)\n");
					}
			    	
			    	
			    // Fall-Through
			    case (RxENABLE) :
			    	if (CHECK_RX_ENABLE(UARTx->CR1, 2)){
			    		printf("	RxEnable: Enabled\n");
			    		SET_REACK(UARTx->ISR, 22);	// Set bit 22 of ISR (REACK)
			    	}
			    	else if(!CHECK_RX_ENABLE(UARTx->CR1, 2)){
			    		printf("	RxEnable: Disabled\n");
			    		CLEAR_REACK(UARTx->ISR, 22);   // Clear bit 22 of ISR (REACK)
			    	}
			    	else{
			    		printf("	Rx Enable set incorrectly (Not expected from fw)\n");
			    	}
			    	terminate = true;	// Temporary, will change when we have more flags to check
			    	break;			    	
			    default :
			    	// Error, and don't hang
			    	printf("CR1 Config not checked\n");
			    	terminate = true;
			    	break;
			}  
		}
	}
	else if	(address == (uint64_t)UARTx->CR2_ADDR){
		UARTx->CR2 = (uint32_t)value;   // Write value written to memory in CR2
		check_flag = STOP_BITS;   	// Temporary, will change with more flags					
		while (!terminate){
			switch (check_flag){
				// Only can be configured when UART Disabled
				/*
					In future, need to check for 0.5, 1.5, 2 stop bits
				*/
				case (STOP_BITS) :
					if (CHECK_STOPBITS1(UARTx->CR2, 13, 12)){
						printf("	Stop bits: 1 Stop Bit (Expected from fw)\n");
					}
					else{
						printf("Stop bit not configured to 1 bit correctly (Not Expected from fw)\n");
					}
	                // Stop checking bits												
					terminate = true;   // Temporary, will change when we have more flags to check
					break;	
				default :
					// Error, and don't hang
					printf("CR2 Config not checked\n");
					terminate = true;
					break;
			}
		}
	}
	
	else if	(address == (uint64_t)UARTx->CR3_ADDR)
		;
	else if	(address == (uint64_t)UARTx->BRR_ADDR){
		UARTx->BRR = (uint32_t)value;   // Read in BaudRate setting
		printf("	Baud Rate Reg set to %x\n", UARTx->BRR);
		if (UARTx->BRR == 0x208D){
			printf(" BaudRate: Set to 9600\n");
		}
	}
	
	else if	(address == (uint64_t)UARTx->GTPR_ADDR)
		;
	else if	(address == (uint64_t)UARTx->RTOR_ADDR)
		;
	else if	(address == (uint64_t)UARTx->RQR_ADDR)
		;
	else if	(address == (uint64_t)UARTx->ISR_ADDR)
		;
	else if	(address == (uint64_t)UARTx->ICR_ADDR){
		check_flag = TCCF; // Manually check TCCF flag
		switch(check_flag)
			case (TCCF) :
				if (CHECK_TCCF(UARTx->ICR, 6))   // bit 6 == TCCF flag
					CLEAR_TC(UARTx->ISR, 6);
			//break;	
	}
	
	else if	(address == (uint64_t)UARTx->RDR_ADDR)		
    	;
	else if	(address == (uint64_t)UARTx->TDR_ADDR){
		// TXE set to '1' by default, no reason to ever clear it to '0'
		// since writes to TDR are redundant and don't affect FW execution
		printf("Write to UART DR: %lu\n", value);   // Check if writes match what should have been read.
			
		// Manually set TC, since it is possible for it to be cleared in FW via ICR register
		SET_TC(UARTx->ISR, 6);	// Set bit 6 of ISR (TC)	
	}
	
	else{
		printf("Address does not match and of UART%d register addresses.\n", uart_i);
		exit(1);
    }	

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
	
	if (address < 0x821c || address > 0x8278)
		printf("How did i make it here: 0x%lx\n", address);
	
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
 
}

/* 
	Compile Command: gcc SimpleUart.c -lunicorn -lpthread
*/
