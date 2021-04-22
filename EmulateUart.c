/*

Compile with:
gcc EmulateUart.c emulatorConfig.c toml.c -lunicorn -lpthread

*/

#include <unicorn/unicorn.h>
#include <string.h>
#include "emulatorConfig.h"

/* USART1 Emulation for stm32l4xx MCUs for ARM Cortex-M */
	   

// Set SP and FP manually for now to some unused memory location
#define FP_INIT      0x02002000
#define SP_INIT      0x02002000

/* MMIO */
//#define MMIO_START   0x40000000
//#define MMIO_SIZE    0x20000000   // (4*1024*131072) 

// Start of USART1 registers. Offsets below
#define USART1_ADDR  0x40013800 
  
// Offsets for USART1 Registers. Easily found in reference manual.
/* 
	In future, offsets may be something the user provides
   	so that we can calculate and use the absolute address below
   	in the enumerated type which is needed for switch-cases.
*/

#define USART1_CR1  0x00
#define USART1_CR2  0x04
#define USART1_CR3  0x08
#define USART1_BRR  0x0C
#define USART1_GTPR 0x10
#define USART1_RTOR 0x14
#define USART1_RQR  0x18
#define USART1_ISR  0x1C
#define USART1_ICR  0x20
#define USART1_RDR  0x24
#define USART1_TDR  0x28


/*** USART1 Configuration Checks ***/
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
// Check if kth bit is set or not in register (Check if USART enabled(1) / disabled(0)) 
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

/*** USART1 Status Register Sets/Clears ***/

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



// Enumerate the addresses of the USART1 registers
enum USART1{
	CR1_ADDR = USART1_ADDR + USART1_CR1,
	CR2_ADDR = USART1_ADDR + USART1_CR2,
	CR3_ADDR = USART1_ADDR + USART1_CR3,
	BRR_ADDR = USART1_ADDR + USART1_BRR,
	GTPR_ADDR = USART1_ADDR + USART1_GTPR,
	RTOR_ADDR = USART1_ADDR + USART1_RTOR,
	RQR_ADDR = USART1_ADDR + USART1_RQR,
	ISR_ADDR = USART1_ADDR + USART1_ISR,
	ICR_ADDR = USART1_ADDR + USART1_ICR,
	RDR_ADDR = USART1_ADDR + USART1_RDR,
	TDR_ADDR = USART1_ADDR + USART1_TDR
};

/*** USART1 Reset Values ***/

/*
	In future, user will need to provide the reset values.
	May get rid of Raw Hex values so user isn't entering two
	sets of reset values.
	WILL GO INTO emulatorConfig.h UART STRUCT
*/

	// User will need to define this in emulatorConfig.toml file
	const uint32_t CR1_RESET = 0x0;
	const uint32_t CR2_RESET = 0x0;
	const uint32_t CR3_RESET = 0x0;
	const uint32_t BRR_RESET = 0x0;
	const uint32_t GTPR_RESET = 0x0;
	const uint32_t RTOR_RESET = 0x0;
	const uint32_t RQR_RESET = 0x0;
	const uint32_t ISR_RESET = 0x020000C0;
	const uint32_t ICR_RESET = 0x0;
	const uint32_t RDR_RESET = 0x0;
	const uint32_t TDR_RESET = 0x0;		


// Enumerate Different USART1 Configurations based on USART1 configuration registers
/* 
2) In future, user may be able to map these configuration checks to particular registers
   instead of hardcoding them for a particular configuration register.
   
   In fact, could have a function that specifically checks the configuration mappings
   and disables certain cases underneath registers that those cases should not be there for
   and enables those congifuration cases for the registers they are mapped to.
   
   In this idea, we would have a copy of the enumerations below for each configuration register
   and just write 0 to the enumerations that are disabled.
   
   If statements might be better for this because 'if(0)' for disabled enumerations would not execute
   but case(0) would execute still.
   
   Once this is configured by user, can move to 3) and user can specifically
   say which bits need to be checked for certain functionality.         
*/
enum USART1_Config{
	ENABLE, 		// Check UART enabled/disabled
	WORDLENGTH,     // Check the word length of USART1 Data (Only possible when USART1 Disabled)
	STOP_BITS,      // Check number of stop bits 			(Only possible when USART1 Disabled) (Ignored   :'(   )
	PARITY_ENABLE, 	// Check if Parity Enabled	   			(Only possible when USART1 Disabled) (Ignored   :'(   )    
	OVERSAMPLE,     // Check oversampling mode				(Only possible when USART1 Disabled)
	BAUDRATE,		// Check baudRate						(Ignored    :'(                    ) 
	TxENABLE,       // Check transmission enable
	RxENABLE,       // Check reception enable
	TCCF			// Check Transmission Complete Clear Flag
};

/*** USART1 Hardware Flags and Masks***/
/* These flags aren't actually available in UART registers, so we declare them here */

bool USART1_enable = false;   // Disabled by default (CR1)

// Mask data to be 7, 8, 9 bits
uint8_t Data_Mask = 0xFF;	  // 8 bits default



// Callback Declarations 
static void pre_read_USART1();
static void post_read_USART1();
static void write_USART1();
static void read_mem();

/*** TEST FUNCTIONS ***/

// Test opcode of binary file to see if it's correct
static void read_op(char * code_ptr, uint32_t program_start, uint32_t code_bytes){
	int index;
	uint32_t start_addr=program_start;
	char * arm_code;
		
	arm_code = code_ptr;	
	for (index=0;index<code_bytes;index=index+4){
		printf("0x%x: %02x%02x%02x%02x\n", start_addr, (uint8_t)arm_code[index], (uint8_t)arm_code[index+1], (uint8_t)arm_code[index+2], (uint8_t)arm_code[index+3]);
		start_addr=start_addr+4;
	}
}

// Test configuration values to see if they match emulatorConfig.toml
static void show_config(){

	printf("FLASH_ADDR: 0x%x\n", FLASH_ADDR);
	printf("FLASH_SIZE: 0x%x\n", FLASH_SIZE);
	printf("SRAM_ADDR:  0x%x\n", SRAM_ADDR);
	printf("SRAM_SIZE:  0x%x\n", SRAM_SIZE);
	printf("MMIO_START: 0x%x\n", MMIO_START);
	printf("MMIO_SIZE:  0x%x\n", MMIO_SIZE);
	printf("CODE_ADDR:  0x%x\n", CODE_ADDR);
	//printf("CODE_SIZE:  0x%x\n", CODE_SIZE);
	printf("DATA_ADDR:  0x%x\n", DATA_ADDR);
	//printf("DATA_SIZE:  0x%x\n", DATA_SIZE);
	printf("START:      0x%x\n", START);
	printf("END:        0x%x\n", END);

}

int main(int argc, char **argv, char **envp)
{
	/* Unicorn Initialization */
	uc_engine *uc;
	uc_err err;
	uc_hook handle1;   // Used by uc_hook_add to give to uc_hook_del() API
	uc_hook handle2;   // Used by uc_hook_add to give to uc_hook_del() API
	uc_hook handle3;   // Used by uc_hook_add to give to uc_hook_del() API
	uc_hook handle4;   // Used by uc_hook_add to give to uc_hook_del() API

    printf("Reading ARM code and data\n");
	/* Read in ARM code here */
	uint32_t code_bytes;
	char *save_addr;
	char *arm_code;
	int byte;
	  	
	FILE *f = fopen("SimpleUart.code.bin", "rb");
	fseek(f, 0L, SEEK_END);  		// Seek to end of file
	code_bytes = ftell(f);    	    // Get size (in bytes) of code from file
	fseek(f, 0L, SEEK_SET); 		// Reset to start of file
	arm_code = (char *) malloc(1*code_bytes);	// Code bytes to be stored
	save_addr = arm_code;
	
	// Read byte at a time from binary file
	for (byte=1; byte<=code_bytes; byte++){
		fread(arm_code, 1, code_bytes, f);
		arm_code++;
	}
	arm_code = save_addr;           // Reset start address	
	fclose(f);
	
	//printf("code_size: 0x%x\n", code_bytes);
	
	/*** TEST: View opcode from file to check if it's correct ***/
	//read_op(arm_code, CODE_ADDR, code_bytes);

	/* Read in ARM data here */
	uint32_t data_bytes;
	char *arm_data;
	
	FILE *g = fopen("SimpleUart.data.bin", "rb");
	fseek(g, 0L, SEEK_END);  		// Seek to end of file
	data_bytes = ftell(g);    		// Get size (in bytes) of data from file
	fseek(g, 0L, SEEK_SET); 		// Reset to start of file
	arm_data = (char *) malloc(1*data_bytes);	// Data bytes to be stored
	save_addr = arm_data;       
	       
	// Read byte at a time from binary file
	for (byte=1; byte<=code_bytes; byte++){
		fread(arm_data, 1, data_bytes, g);
		arm_data++;
	}
	arm_data = save_addr;
	fclose(g);
	
	//printf("data_size: 0x%x\n", data_bytes);
	
	printf("Configure Emulator\n");
	emuConfig();
	/*** TEST: View config variables to check if they match emulatorConfig.toml ***/
	//show_config();
	
    /* ARM Core Registers */	
	uint32_t r_r0 = 0x0000;     // r0
	uint32_t r_r1 = 0x0001;     // r1
	uint32_t r_r2 = 0x0002;     // r2 
	uint32_t r_r3 = 0x0003;     // r3
	uint32_t r_r4 = 0x0004;     // r4
	uint32_t r_r5 = 0x0005;     // r5
	uint32_t r_r6 = 0x0006;     // r6
	uint32_t r_r7 = 0x0007;     // r7 
	uint32_t r_r8 = 0x0008;     // r8
	uint32_t r_r9 = 0x0009;     // r9
	uint32_t r_r10 = 0x000A;    // r10
	uint32_t FP = FP_INIT;      // r11  
	uint32_t r_r12 = 0x000C;    // r12
	uint32_t SP = SP_INIT;      // r13  

	printf("Emulate arm code\n");
	
	// Create new instance of unicorn engine (Init the emulator)
	err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
	if (err != UC_ERR_OK){
		printf("Failed on uc_open() with error returned: %u\n", err);
		return -1;
	}
	
	/*** Memory Map ***/
	// Map Flash region
	if (uc_mem_map(uc, FLASH_ADDR, FLASH_SIZE, UC_PROT_ALL)){
		printf("Failed to map flash region to memory. Quit\n");
		return -1;
	}
	// Map SRAM region
	if (uc_mem_map(uc, SRAM_ADDR, SRAM_SIZE, UC_PROT_ALL)){
		printf("Failed to map sram region to memory. Quit\n");
		return -1;	
	}		
	// Map all MMIO from 0x40000000 - 0x5FFFFFFF
	if (uc_mem_map(uc, MMIO_START, MMIO_SIZE, UC_PROT_ALL)){
		printf("Failed to map MMIO region to memory. Quit\n");
		return -1;
	}
	/*** Memory Init ***/
	// Write code to flash!
	if (uc_mem_write(uc, CODE_ADDR, arm_code, code_bytes)){ // -1 because of null byte
		printf("Failed to write code to memory. Quit\n");
		return -1;
	}
	free(arm_code);
	
	// Write data to flash!
	if (uc_mem_write(uc, DATA_ADDR, arm_data, data_bytes)){ // -1 because of null byte
		printf("Failed to write code to memory. Quit\n");
		return -1;
	}
	free(arm_data);

	/*
		May do a batch write in the future to decrease code size, if possible
	*/
	// Initialize all UART registers to their reset values
	if (uc_mem_write(uc, CR1_ADDR , &CR1_RESET, 4)){
		printf("Failed to Initialize CR1. Quit\n");
		return -1;
	}
	if (uc_mem_write(uc, CR2_ADDR , &CR2_RESET, 4)){
		printf("Failed to Initialize CR2. Quit\n");
		return -1;		
	}
	if (uc_mem_write(uc, CR3_ADDR , &CR3_RESET, 4)){
		printf("Failed to Initialize CR3. Quit\n");
		return -1;	
	}
	if (uc_mem_write(uc, BRR_ADDR , &BRR_RESET, 4)){
		printf("Failed to Initialize BRR. Quit\n");
		return -1;	
	}
	if (uc_mem_write(uc, GTPR_ADDR , &GTPR_RESET, 4)){
		printf("Failed to Initialize GTPR. Quit\n");
		return -1;	
	}
	if (uc_mem_write(uc, RTOR_ADDR , &RTOR_RESET, 4)){
		printf("Failed to Initialize RTOR. Quit\n");
		return -1;	
	}
	if (uc_mem_write(uc, RQR_ADDR , &RQR_RESET, 4)){
		printf("Failed to Initialize RQR. Quit\n");
		return -1;	
	}
	if (uc_mem_write(uc, ISR_ADDR , &ISR_RESET, 4)){
		printf("Failed to Initialize ISR. Quit\n");
		return -1;	
	}
	if (uc_mem_write(uc, ICR_ADDR , &ICR_RESET, 4)){
		printf("Failed to Initialize ICR. Quit\n");
		return -1;	
	}
	if (uc_mem_write(uc, RDR_ADDR , &RDR_RESET, 4)){
		printf("Failed to Initialize RDR. Quit\n");
		return -1;	
	}
	if (uc_mem_write(uc, TDR_ADDR , &TDR_RESET, 4)){
		printf("Failed to Initialize TDR. Quit\n");
		return -1;	
	}
		
	// Callback to handle FW reads before they happen. (Update values in memory before they are read)
	uc_hook_add(uc, &handle1, UC_HOOK_MEM_READ, pre_read_USART1, NULL, USART1_ADDR, USART1_ADDR + USART1_TDR);
	
	// Callback to handle FW reads after they happen. (Update certain registers after reads)
	uc_hook_add(uc, &handle2, UC_HOOK_MEM_READ_AFTER, post_read_USART1, NULL, USART1_ADDR, USART1_ADDR + USART1_TDR);	
	
	// Callback to handle when FW writes to any USART1 register (DR and CR. SR should change according to CR write.) 
	uc_hook_add(uc, &handle3, UC_HOOK_MEM_WRITE, write_USART1, NULL, USART1_ADDR, USART1_ADDR + USART1_TDR);
			
	// Callback to check memory/debug at any code address (specific addresses can be defined in callback)
	uc_hook_add(uc, &handle4, UC_HOOK_CODE, read_mem, NULL, FLASH_ADDR, FLASH_ADDR + FLASH_SIZE);	
			
	// Init registers that may be used by FW
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

		
	err=uc_emu_start(uc, START, END, 0, 0);
	if (err){
		printf("Failed on uc_emu_start() with error returned %u: %s\n", err, uc_strerror(err));
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

	// Needs changed to reflect new ending values
	printf("r0 = 0x%x \n",r_r0);
	printf("r1 = 0x%x \n",r_r1);
	printf("r2 = 0x%x \n",r_r2);
	printf("r3 = 0x%x \n",r_r3);
	printf("r4 = 0x%x \n",r_r4);
	printf("r5 = 0x%x \n",r_r5);
	printf("r6 = 0x%x \n",r_r6);
	printf("r7 = 0x%x \n",r_r7);
	printf("r8 = 0x%x \n",r_r8);
	printf("r9 = 0x%x \n",r_r9);
	printf("r10 = 0x%x \n",r_r10);
	printf("FP = 0x%x \n",FP);
	printf("r12 = 0x%x \n",r_r12);
	printf("SP = 0x%x \n",SP);
	
	return 0;
}

// When FW reads from RDR (Before successful read)
static void pre_read_USART1(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, uint64_t value, void *user_data)
{
	printf("Made it to pre_read_USART1 callback\n");
    uint32_t Data;  // For RDR
    switch(address){
    	case (CR1_ADDR) :   		
    		break;
    	case (CR2_ADDR) :
    		break;		
    	case (CR3_ADDR) :
    		break;
    	case (BRR_ADDR) :
    		break;
    	case (GTPR_ADDR) :
    		break;
    	case (RTOR_ADDR) :
    		break;
    	case (RQR_ADDR) :
    		break;
    	case (ISR_ADDR) :
    		printf("	Update ISR\n");
    		/*
    			bits 25, 7, & 6 are set by default in ISR.
    			25 is undetermined atm
    			7 & 6 never change, since there is no logical reason to ever change them
    		*/
    		// Commit the current ISR value to memory before fw reads it
    		uc_mem_write(uc, ISR_ADDR, &USART1.ISR, 4);
    		break;
    	case (ICR_ADDR) :
    		break; 		
    	// (Preload data for now ... )
    	case (RDR_ADDR) :
    		printf("	Update Data Register\n") ;
    		Data = 0xEE;		
    		// Mask should be 7 bit in this test (Data == 0x6E)
    		Data &= Data_Mask;		// Mask according to 7, 8, 9 bit data 
    		USART1.RDR = Data;
    			printf("	DR val: 0x%x\n", Data);		
    		uc_mem_write(uc, RDR_ADDR, &USART1.RDR, 4);
    		// Data is loaded into DR at this point, so RXNE == 1
    		SET_RXNE(USART1.ISR, 5);   // Set bit 5 (RXNE)    		
    		break;
    	case (TDR_ADDR) :
    		break;	
    }                                     
}

// When FW reads from RDR (After successful read)
static void post_read_USART1(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, uint64_t value, void *user_data)
{
    printf("Made it to post_read_USART1 callback\n");
    switch(address){
    	case (CR1_ADDR) :   		
    		break;
    	case (CR2_ADDR) :
    		break;		
    	case (CR3_ADDR) :
    		break;
    	case (BRR_ADDR) :
    		break;
    	case (GTPR_ADDR) :
    		break;
    	case (RTOR_ADDR) :
    		break;
    	case (RQR_ADDR) :
    		break;
    	case (ISR_ADDR) :
    		break;
    	case (ICR_ADDR) :
    		break; 		
    	case (RDR_ADDR) : 
    		printf("	Clear DR after read\n");
    		// Data Register should be cleared after it's read
    		USART1.RDR = 0;	
    		printf("	DR Val:0x%x\n", USART1.RDR);	
    		uc_mem_write(uc, RDR_ADDR, &USART1.RDR, 4);
    		// Data has been read already, so RXNE == 0
    		CLEAR_RXNE(USART1.ISR, 5);   // Clear bit 5 (RXNE) 	 		
    		break;
    	case (TDR_ADDR) :
    		break;	
    }                                     
}

// When FW writes writes to USART1 MMIO (Data and Control Registers) 
static void write_USART1(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, uint64_t value, void *user_data)
{
	printf("Made it to write_USART1 callback\n\n");
	/*	
	    Certain Emulation Exceptions:
		1) If USART1 is enabled, certain bits in multiple registers cannot be written to.
		   It's assumed that the FW disabled/enables USART1 accordingly and that the FW has
		   previously been ran on an actual device. Therefore, enable/disable checks are emitted 
		   from the emulator.
	*/

	bool terminate = false;			 		// Terminate register checks/writes when true
	uint8_t Check_Config;					// Change state of switch-case statements for configuration registers
	
	// Choose which register to write to based on it's address
	switch(address){
	    // Write to CR1
		case (CR1_ADDR) :
			printf("Configure CR1\n");
			/*
				In future, will likely revert to if-statements in the future 
				to check what configurations the user disabled/enabled. 
				   Disabled configs will be zero.   (therefore not executed)
				   Enabled configs will be non-zero (therefore executed)
			*/			
			USART1.CR1 = (uint32_t)value;    // Save value written to memory in CR1
			Check_Config = ENABLE;   // Check if USART1 enabled first
			while (!terminate){
				switch (Check_Config){

					case (ENABLE) :
					    // Check if bit 0 of CR1 is set
						if (CHECK_ENABLE(USART1.CR1, 0)){
							printf("	Enable: USART Enabled\n");
							USART1_enable = true;            // May not need to check if USART1 is enabled/disabled anymore					
							Check_Config = TxENABLE;   		 // Skip all cases that require disabled USART1
						}
						// USART1 Disabled, so reset ISR
						else{
							printf("	Enable: USART Disabled\n");
							USART1_enable = false;			// May not need to check if USART1 is enabled/disabled anymore
							USART1.ISR = ISR_RESET;
							uc_mem_write(uc, ISR_ADDR, &USART1.ISR, 4);   // Update status register	
							Check_Config = WORDLENGTH;
						}
						break;
					
					/*
						In future, need to check for 9 bit configuration as well
					*/
					// Only can be configured when USART1 Disabled
					case (WORDLENGTH) :  
						// Check if both bits are 0.
						if (CHECK_WORDLENGTH8(USART1.CR1, 28, 12)){
							printf("	WordLength: 8 Bit Data\n");
							Data_Mask = 0xFF;	// 8 bit data (somewhat redundant )
						}
						// Check if bit 28 is 1 and bit 12 is 0
						else if (CHECK_WORDLENGTH7(USART1.CR1, 28, 12)){
							printf("	WordLength: 7 Bit Data\n");
							Data_Mask = 0x7F;	// 7 bit data
						}
						
					// Fall-Through
					/*
						In some cases fw may be able to red parity bit
					*/
					// Only can be configured when USART1 Disabled
					case (PARITY_ENABLE) :
						if (CHECK_PARITY_EN(USART1.CR1, 10)){
							printf("	ParityEnable: Enabled\n");  	// Let us know it was set 
						}
						else if (!CHECK_PARITY_EN(USART1.CR1, 10)){
							printf("	ParityEnable: Disabled\n");  	// Let us know it wasn't set (Expected Result)
						}
						else{
							printf("	Parity set incorrectly (Not expected from fw)\n");
						}
						
					// Fall-Through
					// Only can be configured when USART1 Disabled
					case (OVERSAMPLE) :
					
						if (CHECK_OVERSAMPLE(USART1.CR1, 15)){
							printf("	Oversample: Oversample 8 Set\n");
						}
						else if (!CHECK_OVERSAMPLE(USART1.CR1, 15)){
							printf("	Oversample: Oversample 16 Set\n");
						}
						else{
							printf("	Oversample set incorrectly (Not expected from fw)\n");
						}
						
			    	// Fall-Through
			    	case (TxENABLE) :
			    		if (CHECK_TX_ENABLE(USART1.CR1, 3)){
			    			printf("	TxEnable: Enabled\n");
			    			SET_TEACK(USART1.ISR, 21);   	// Set bit 21 of ISR (TEACK)
			    		}
			    		else if (!CHECK_TX_ENABLE(USART1.CR1, 3)){
			    			printf("	TxEnable: Disabled\n");
			    			CLEAR_TEACK(USART1.ISR, 21);   	// Clear bit 21 of ISR (TEACK)
			    		}
						else {
							printf("	Tx Enable set incorrectly (Not expected from fw)\n");
						}
			    	
			    	
			    	// Fall-Through
			    	case (RxENABLE) :
			    		if (CHECK_RX_ENABLE(USART1.CR1, 2)){
			    			printf("	RxEnable: Enabled\n");
			    			SET_REACK(USART1.ISR, 22);	// Set bit 22 of ISR (REACK)
			    		}
			    		else if(!CHECK_RX_ENABLE(USART1.CR1, 2)){
			    			printf("	RxEnable: Disabled\n");
			    			CLEAR_REACK(USART1.ISR, 22);   // Clear bit 22 of ISR (REACK)
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
			// Break CR1    	
			break;	
		// Write to CR2	
		case (CR2_ADDR) :
		
			USART1.CR2 = (uint32_t)value;   // Write value written to memory in CR2
			Check_Config = STOP_BITS;   	// Temporary, will change with more flags					
			while (!terminate){
				switch (Check_Config){
					// Only can be configured when USART1 Disabled
					/*
						In future, need to check for 0.5, 1.5, 2 stop bits
					*/
					case (STOP_BITS) :
						if (CHECK_STOPBITS1(USART1.CR2, 13, 12)){
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
			
			break;
		case (CR3_ADDR) :
			break;		
		/*
			In future, may be nice to actually compute the baudrate chosen
			rather than knowing ahead of time.
		*/
		case (BRR_ADDR) :
			USART1.BRR = (uint32_t)value;   // Read in BaudRate setting
			printf("	Baud Rate Reg set to %x\n", USART1.BRR);
			if (USART1.BRR == 0x208D){
				printf(" BaudRate: Set to 9600\n");
			}
			break;
			
		case (GTPR_ADDR) :
		
			break;		
		case (RTOR_ADDR) :
		
			break;		
		case (RQR_ADDR) :
		
			break;		
		case (ISR_ADDR) :
		
			break;		
		case (ICR_ADDR) :
			Check_Config = TCCF; // Manually check TCCF flag
			switch(Check_Config)
				case (TCCF) :
					if (CHECK_TCCF(USART1.ICR, 6))   // bit 6 == TCCF flag
						CLEAR_TC(USART1.ISR, 6);
				break;	
				
			break;		
		// Read Only so never used here	
		case (RDR_ADDR) :
			break;		
		case (TDR_ADDR) :
			// TXE set to '1' by default, no reason to ever clear it to '0'
			// since writes to TDR are redundant and don't affect FW execution
			printf("Write to USART1 DR: %lu\n", value);   // Check if writes match what should have been read.
			
			// Manually set TC, since it is possible for it to be cleared in FW via ICR register
			SET_TC(USART1.ISR, 6);	// Set bit 6 of ISR (TC)		
			break;	
 		default :
 			// Error, Case statements above expected to be executed.
 			printf("No USART1 register written to when it should have been.\n");
			break;
	}

}

// Test code at particular execution addresses to read memory and debug
static void read_mem(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{   
    /*
	uint32_t r_r2;
	uint32_t r_r3;			
	uint32_t var;	
	*/
	
    /* 
    	Function: 'USART_Init'
    	CR1: Should be 0x1000000d at this point
    */
    /*
    THIS IS ALL FOR THE COMPLICATED POLLINGUART
    if (address == 0x100b4){
    	// CR1 is in r2 at this point
    	uc_reg_read(uc, UC_ARM_REG_R2, &r_r2);
    	printf("CR1 in r2: 0x%x\n", r_r2);
    }
    if (address == MAIN_START)
    	printf("Made it to Main\n");
    	
    if (address == 0x10000)
    	printf("Made it inside USART_init\n");
    	
    if (address == 0x10258)
    	printf("Made it after USART_init call\n");
    
    // Testing if register values match expected values
    if (address == 0x10244){
    	uc_reg_read(uc, UC_ARM_REG_R11, &var);
    	printf("FP: 0x%x\n",var);				
    }
    */
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
	CR1 bits that can only be written to when USART1 is Disabled.
	xWordLength	 				 	[28,12]
	Driver Enable Assertion time 	[25:21]
	Driver Enable de-assertion time [20:16]
	xOversampling Mode 				[15]
	Receiver Wakeup Method			[11]
	xParity Control enable			[10]
	Parity Selection				[9]	
*/

/* 
	Compile Command: gcc SimpleUart.c -lunicorn -lpthread
*/
