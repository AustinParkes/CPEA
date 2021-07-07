#include "tester.h"
#include "emulatorConfig.h"

// Test configuration values in emulatorConfig.h to see if they match emulatorConfig.toml
void show_config(){
	printf("\n*** Emulator Config ***\n");
	printf("CODE_ADDR: 0x%x\n", CODE_ADDR);
	printf("CODE_SIZE: 0x%x\n", CODE_SIZE);
	printf("SRAM_ADDR:  0x%x\n", SRAM_ADDR);
	printf("SRAM_SIZE:  0x%x\n", SRAM_SIZE);
	printf("MMIO_ADDR:  0x%x\n", MMIO_ADDR);
	printf("MMIO_SIZE:  0x%x\n", MMIO_SIZE);
	printf("CODE_ADDR:  0x%x\n", CODE_ADDR);
	//printf("CODE_SIZE:  0x%x\n", CODE_SIZE);
	printf("DATA_ADDR:  0x%x\n", DATA_ADDR);
	//printf("DATA_SIZE:  0x%x\n", DATA_SIZE);
	printf("START:      0x%x\n", START);
	printf("END:        0x%x\n", END);
	
	printf("\nSP_INIT:  0x%x\n", SP);
	printf("FP_INIT:  0x%x\n", FP);	
	//show_structures();
}

// Show a peripherals main data structure.
void show_structures(){

	uint32_t *periph_ptr;		// Point to a particular UART module
	printf("\n*** UART Structures ***\n");
	for (int mod_i=0; mod_i<mod_count; mod_i++){
		periph_ptr = (uint32_t *)MMIO[mod_i];
		printf("mod%d Base:  0x%x\n", mod_i, *periph_ptr);
		periph_ptr++;
		for (int i=1; i<23; i++){
			if (i <= 11)
				printf("mod%d addr:  0x%x\n", mod_i, *periph_ptr);
			else
				printf("mod%d reset: 0x%x\n", mod_i, *periph_ptr);
			periph_ptr++;
		}
	}
}

// Test opcode (or data) of binary file to see if it's correct
void read_fbin(char * code_ptr, uint32_t program_start, uint32_t code_bytes){
	int index;
	uint32_t start_addr=program_start;
	char * arm_code;
		
	arm_code = code_ptr;	
	for (index=0; index<code_bytes; index=index+4){
		printf("0x%x: %02x%02x%02x%02x\n", start_addr, (uint8_t)arm_code[index], (uint8_t)arm_code[index+1], (uint8_t)arm_code[index+2], (uint8_t)arm_code[index+3]);
		start_addr=start_addr+4;
	}
}

// Show registers r0-r14
void show_regs(){

	printf("\n*** Registers ***\n");
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
	printf("LR = 0x%x \n",LR);
}

// Show memory contents of mmio
void show_mmio(uc_engine *uc){
	show_UART(uc);
}

// Show memory contents of UART mmio.
void show_UART(uc_engine *uc){
	
	int i;		// Iterate through UART modules.
	
	// Save mmio register contents to these variables. 
	uint32_t CR1;
	uint32_t CR2;
	uint32_t CR3;
	uint32_t CR4;
	uint32_t CR5;
	uint32_t CR6;
	uint32_t CR7;
	uint32_t CR8;
	uint32_t CR9;
	uint32_t SR1;
	uint32_t SR2;
	uint32_t DR1;
	uint32_t DR2;
	
	printf("\n*** Show UART mmio contents ***\n");

	for (i=0; i<mod_count; i++){
	
		
		if ((MMIO[i]->SR_ADDR[SR1] >= minPeriphaddr) && (MMIO[i]->SR_ADDR[SR1] <= maxPeriphaddr))
			uc_mem_read(uc, MMIO[i]->SR_ADDR[SR1], &SR1, 4);
		if ((MMIO[i]->SR_ADDR[SR2] >= minPeriphaddr) && (MMIO[i]->SR_ADDR[SR2] <= maxPeriphaddr))
			uc_mem_read(uc, MMIO[i]->SR_ADDR[SR2], &SR2, 4);
		if ((MMIO[i]->DR_ADDR[DR1] >= minPeriphaddr) && (MMIO[i]->DR_ADDR[DR1] <= maxPeriphaddr))
			uc_mem_read(uc, MMIO[i]->DR_ADDR[DR1], &DR1, 4);
		if ((MMIO[i]->DR_ADDR[DR2] >= minPeriphaddr) && (MMIO[i]->DR_ADDR[DR2] <= maxPeriphaddr))
			uc_mem_read(uc, MMIO[i]->DR_ADDR[DR2], &DR2, 4);
		
		printf("UART%d SR1:  0x%x\n", i, SR1);
		printf("UART%d SR2:  0x%x\n", i, SR2);
		printf("UART%d DR1:  0x%x\n", i, DR1);
		printf("UART%d DR2:  0x%x\n", i, DR2);	
	}
	
}
