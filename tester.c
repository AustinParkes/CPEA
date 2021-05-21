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
void read_op(char * code_ptr, uint32_t program_start, uint32_t code_bytes){
	int index;
	uint32_t start_addr=program_start;
	char * arm_code;
		
	arm_code = code_ptr;	
	for (index=0; index<code_bytes; index=index+4){
		printf("0x%x: %02x%02x%02x%02x\n", start_addr, (uint8_t)arm_code[index], (uint8_t)arm_code[index+1], (uint8_t)arm_code[index+2], (uint8_t)arm_code[index+3]);
		start_addr=start_addr+4;
	}
}
