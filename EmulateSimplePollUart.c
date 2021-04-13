/*
Compile with: 
gcc EmulateSimplePollUart.c -lunicorn -lpthread
*/

#include <unicorn/unicorn.h>

// Memory Map for Code and Data
#define VIRT_ADDR    0x00000000
#define VIRT_SIZE    0x00019000

// Memory start addresses and sizes

//.text section
#define TEXT_ADDR    0x00008018
#define TEXT_SIZE    0x00000668

//.data section
#define DATA_ADDR	0x000186b8
#define DATA_SIZE	0x00000438

// Execution Entry and End
#define MAIN	0x00008274 
#define END		0x000082a0 

// Initial SP/FP Bottom Boundaries  (Choosing a free location)
#define SP_INIT   0x00024000
#define FP_INIT   0x00024000

#define STACK_SIZE	0x00005000	// Choosing arbitrary value for now

#define STACK_TOP	0x00025000	// Where SP starts

// Memory Map for MMIO 0x40000000 - 0x5fffffff
#define MMIO_START   0x40000000
#define MMIO_SIZE    0x20000000   // (4*1024*131072) 

// Write to memory
#define UART_ADDR    0x40013800
#define UART_SIZE    4*1024

// Matches fw
#define UART_CR1_ADDR 0x40013800

// Matches fw
#define UART_DR_ADDR 0x40013824

// Check if any 2 bits are both 0. (Check if UART 8-N-1)
#define CHECK2N(n,k1,k2)  (~n & (1<<k1)) && (~n & (1<<k2))

// Check among 2 bits if 1 is set and the other is not set. (check if UART 7-N-1)
#define CHECK1S1N(n, k1Set, k2Not)  (n & (1<<k1Set)) && (~n & (1<<k2Not))

/* 
   UART periphal registers
*/
typedef struct UART{
	uint32_t CR1;
	uint32_t CR2;
	uint32_t CR3;
	uint32_t BRR;
	uint32_t GTPR;
	uint32_t RTOR;
	uint32_t RQR;
	uint32_t ISR;
	uint32_t ICR;
	uint32_t RDR;
	uint32_t TDR;
} UART_handle;

// Update this structure with QEMU's MMIO memory 
UART_handle UART;

static void read_DR();
static void write_CR1();
static void read_mem();

int main(int argc, char **argv, char **envp)
{
	uc_engine *uc;
	uc_err err;
	uc_hook handle1;   // Used by uc_hook_add to give to uc_hook_del() API
	uc_hook handle2;   // Used by uc_hook_add to give to uc_hook_del() API
	uc_hook handle3;   // Used by uc_hook_add to give to uc_hook_del() API
	
	// Read code into file

	//int code_size;	
	FILE *f = fopen("SimplePollUart.bin.text", "r");
	//fseek(f, 0L, SEEK_END);  		// Seek to end of file
	//code_size = ftell(f);    		// Get size of code from file
	//fseek(f, 0L, SEEK_SET); 		// Reset to start of file
	char code[TEXT_SIZE+1]={0};     // TODO: Dynamically allocate in the future
	if (fgets(code, TEXT_SIZE+1, f) == NULL){  // Store code in buf
		printf("Error reading from file\n");
	}
	fclose(f);
	
	// Read data into file
	FILE *g = fopen("SimplePollUart.bin.data", "r");
	//fseek(g, 0L, SEEK_END);  		// Seek to end of file
	//code_size = ftell(g);    		// Get size of code from file
	//fseek(g, 0L, SEEK_SET); 		// Reset to start of file
	char data[DATA_SIZE+1]={0};     // TODO: Dynamically allocate in the future
	if (fgets(data, DATA_SIZE+1, g) == NULL){  // Store code in buf
		printf("Error reading from file\n");
	}
	fclose(g);
	
	uint32_t r_r0 = 0x0000;
	uint32_t r_r1 = 0x0001;
	uint32_t r_r2 = 0x0002;
	uint32_t r_r3 = 0x0003;
	uint32_t r_r4 = 0x0004;
	uint32_t r_r5 = 0x0005;
	uint32_t r_r6 = 0x0006;
	uint32_t r_r7 = 0x0007;
	uint32_t r_r8 = 0x0008;     
	uint32_t r_r9 = 0x0009;    
	uint32_t r_r10 = 0x000A;   		
	uint32_t FP = STACK_TOP;
	uint32_t r_r12 = 0x000C;	
	uint32_t SP = STACK_TOP;  // Stack grows down so start at the top
	
	printf("Emulate arm code\n");
	
	// Create new instance of unicorn engine (Init the emulator)
	err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
		if (err != UC_ERR_OK){
			printf("Failed on uc_open() with error returned: %u\n", err);
			return -1;
	}
	
	// Map the program (will be .text and .data section and their size)
	if (uc_mem_map(uc, VIRT_ADDR, VIRT_SIZE, UC_PROT_ALL)){
		printf("Failed to map code to memory. Quit\n");
		return -1;
	}
	
	// Map stack memory
	if (uc_mem_map(uc, SP_INIT, STACK_SIZE, UC_PROT_ALL)){
		printf("Failed to map stack region to memory. Quit\n");
		return -1;
	}	
	
	// Map UART MMIO
	if (uc_mem_map(uc, MMIO_START, MMIO_SIZE, UC_PROT_ALL)){
		printf("Failed to map MMIO to memory. Quit\n");
		return -1;
	}
	
	// .text section
	// Write machine code to memory!
	//              (uc, start_addr, ptr_to_write, size of data to write)
	if (uc_mem_write(uc, TEXT_ADDR, code, sizeof(code)-1)){
		printf("Failed to write code to memory. Quit\n");
		return -1;
	}
	
	// .data Section
	// Write data to memory!
	if (uc_mem_write(uc, DATA_ADDR, data, sizeof(data)-1)){
		printf("Failed to write code to memory. Quit\n");
		return -1;
	}
	
	// Initialize CR1 to 0
	if (uc_mem_write(uc, UART_CR1_ADDR, "\x00\x00\x00\x00", 4)){
		printf("Failed to initialize UART registers. Quit\n");
		return -1;
	}
	
	// Initialize DR to 0
	if (uc_mem_write(uc, UART_DR_ADDR, "\x00\x00\x00\x00", 4)){
		printf("Failed to initialize UART registers. Quit\n");
		return -1;
	}
	
	// Add callback to data register access
	// Hooked inclusively to UART DR address
	uc_hook_add(uc, &handle1, UC_HOOK_MEM_READ, read_DR, NULL, UART_DR_ADDR, UART_DR_ADDR);	
	uc_hook_add(uc, &handle2, UC_HOOK_MEM_WRITE, write_CR1, NULL, UART_CR1_ADDR, UART_CR1_ADDR);
	
	// Used for debugging, tracking flow of code, reading memory at certain points of execution	
	uc_hook_add(uc, &handle3, UC_HOOK_CODE, read_mem, NULL, TEXT_ADDR, TEXT_ADDR + TEXT_SIZE);
	
	// Init the registers to be written to
	uc_reg_write(uc, UC_ARM_REG_R0, &r_r0);
	uc_reg_write(uc, UC_ARM_REG_R1, &r_r1);
	uc_reg_write(uc, UC_ARM_REG_R2, &r_r2);
	uc_reg_write(uc, UC_ARM_REG_R3, &r_r3);
	uc_reg_write(uc, UC_ARM_REG_R4, &r_r4);
	uc_reg_write(uc, UC_ARM_REG_R5, &r_r5);
	uc_reg_write(uc, UC_ARM_REG_R6, &r_r6);
	uc_reg_write(uc, UC_ARM_REG_R7, &r_r7);
	uc_reg_write(uc, UC_ARM_REG_R8, &r_r8);   
	uc_reg_write(uc, UC_ARM_REG_R9, &r_r9); 	
	uc_reg_write(uc, UC_ARM_REG_R10, &r_r10);		
	if (uc_reg_write(uc, UC_ARM_REG_FP, &FP))
		printf("FP error\n");
	uc_reg_write(uc, UC_ARM_REG_R12, &r_r12);	
	if (uc_reg_write(uc, UC_ARM_REG_SP, &SP))
		printf("SP error\n");


	// Begin emulation
	err=uc_emu_start(uc, MAIN, END, 0, 0);
	
	if (err){
		printf("Failed on uc_emu_start() with error returned %u: %s\n", err, uc_strerror(err));
	}
	
	// Read end results in registers to understand emulation
	uc_reg_read(uc, UC_ARM_REG_R0, &r_r0);
	uc_reg_read(uc, UC_ARM_REG_R1, &r_r1);
	uc_reg_read(uc, UC_ARM_REG_R2, &r_r2);
	uc_reg_read(uc, UC_ARM_REG_R3, &r_r3);
	uc_reg_read(uc, UC_ARM_REG_R4, &r_r4);
	uc_reg_read(uc, UC_ARM_REG_R5, &r_r5);
	uc_reg_read(uc, UC_ARM_REG_R6, &r_r6);
	uc_reg_read(uc, UC_ARM_REG_R7, &r_r7);
	uc_reg_read(uc, UC_ARM_REG_R8, &r_r8);	
	uc_reg_read(uc, UC_ARM_REG_R9, &r_r9);		
	uc_reg_read(uc, UC_ARM_REG_R10, &r_r10);	
	uc_reg_read(uc, UC_ARM_REG_FP, &FP);
	uc_reg_read(uc, UC_ARM_REG_R12, &r_r12);	
	uc_reg_read(uc, UC_ARM_REG_SP, &SP);
	
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

// When FW reads from RDR
static void read_DR(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, uint64_t value, void *user_data)
{
    /*Check if UART config is 7-N-1 or 8-N-1 */  
	printf("Read_DR Callback\n");
	if (CHECK2N(UART.CR1, 28, 12)){   					// Check for 8-N-1
		UART.RDR = 0xFF;
 		uc_mem_write(uc, UART_DR_ADDR, &UART.RDR, 4);  	// Provide DR input for FW to read
 	}
 	else if (CHECK1S1N(UART.CR1, 28, 12)){  			// Check for 7-N-1
 		UART.RDR = 0x7F;
 		uc_mem_write(uc, UART_DR_ADDR, &UART.RDR, 4);  	// Provide DR input for FW to read
 	}                                           
}


// When FW writes to CR1
static void write_CR1(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, uint64_t value, void *user_data)
{
	printf("Write_CR1 Callback\n");
	// Update our CR1 value in struct
	UART.CR1 = (uint32_t)value;

}

// Modify this to read any memory at any point of time 
static void read_mem(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint32_t r_r3;
	uint32_t var1;
	uint32_t var2;

	// Check if we are branching
    if (address == 0x8274){
    	printf("Made it inside main\n");
    	uc_mem_read(uc, 0x186bc, &var1, 4);
    	printf("[0x186bc]: %x\n", var1);
    }

    if (address == 0x8278){
    	printf("2nd instr\n");
    }

    if (address == 0x827c){
    	printf("3rd instr\n");
    }

    if (address == 0x8280){
    	printf("4th instr\n");
    }

	if (address == 0x828c){
    	printf("Made it to the read_DR call\n");
    }

    if (address == 0x8244){
    	printf("Made it inside read_DR\n");
    }
    
    if (address == 0x82a0){
    	printf("Made it to end of main\n");
    }
    
}
        
    
/* 
Compile Command: gcc test.c -L. -lpthread -lm -lunicorn
*/





















