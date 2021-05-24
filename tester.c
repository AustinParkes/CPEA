#include "tester.h"
#include "emulatorConfig.h"

// Test configuration values in emulatorConfig.h to see if they match emulatorConfig.toml
void show_config(){
	printf("\n*** Emulator Config ***\n");
	printf("FLASH_ADDR: 0x%x\n", FLASH_ADDR);
	printf("FLASH_SIZE: 0x%x\n", FLASH_SIZE);
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

	uint32_t *UART_ptr;		// Point to a particular UART module
	printf("\n*** UART Structures ***\n");
	for (int uart_i=0; uart_i<uart_count; uart_i++){
		UART_ptr = (uint32_t *)UART[uart_i];
		printf("UART%d Base:  0x%x\n", uart_i, *UART_ptr);
		UART_ptr++;
		for (int i=1; i<23; i++){
			if (i <= 11)
				printf("UART%d addr:  0x%x\n", uart_i, *UART_ptr);
			else
				printf("UART%d reset: 0x%x\n", uart_i, *UART_ptr);
			UART_ptr++;
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
	uint32_t BRR;
	uint32_t GTPR;
	uint32_t RTOR;
	uint32_t RQR;
	uint32_t ISR;
	uint32_t ICR;
	uint32_t RDR;
	uint32_t TDR;
	
	printf("\n*** Show UART mmio contents ***\n");

	for (i=0; i<uart_count; i++){
		uc_mem_read(uc, UART[i]->CR1_ADDR, &CR1, 4);
		uc_mem_read(uc, UART[i]->CR2_ADDR, &CR2, 4);
		uc_mem_read(uc, UART[i]->CR3_ADDR, &CR3, 4);
		uc_mem_read(uc, UART[i]->BRR_ADDR, &BRR, 4);
		uc_mem_read(uc, UART[i]->GTPR_ADDR, &GTPR, 4);
		uc_mem_read(uc, UART[i]->RTOR_ADDR, &RTOR, 4);
		uc_mem_read(uc, UART[i]->RQR_ADDR, &RQR, 4);
		uc_mem_read(uc, UART[i]->ISR_ADDR, &ISR, 4);
		uc_mem_read(uc, UART[i]->ICR_ADDR, &ICR, 4);
		uc_mem_read(uc, UART[i]->RDR_ADDR, &RDR, 4);
		uc_mem_read(uc, UART[i]->TDR_ADDR, &TDR, 4);
		printf("UART%d CR1:  0x%x\n", i, CR1);
		printf("UART%d CR2:  0x%x\n", i, CR2);
		printf("UART%d CR3:  0x%x\n", i, CR3);
		printf("UART%d BRR:  0x%x\n", i, BRR);
		printf("UART%d GTPR: 0x%x\n", i, GTPR);
		printf("UART%d RTOR: 0x%x\n", i, RTOR);
		printf("UART%d RQR:  0x%x\n", i, RQR);
		printf("UART%d ISR:  0x%x\n", i, ISR);
		printf("UART%d ICR:  0x%x\n", i, ICR);
		printf("UART%d RDR:  0x%x\n", i, RDR);
		printf("UART%d TDR:  0x%x\n", i, TDR);	
	}
	
}
