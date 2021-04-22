/* Parse emulatorConfig.toml and extract values important for the emulator 
 *
 *
*/

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "emulatorConfig.h"
#include "toml.h"

static void error(const char *msg, const char* msg1)
{
	fprintf(stderr, "ERROR: %s%s\n", msg, msg1?msg1:"");
	exit(1);
}

// Read config file and parse emulator configurations
void emuConfig(){
	
	FILE *fp;
	char errbuf[200];

	/*
		Read and Parse configuration file
	*/
	
	fp = fopen("emulatorConfig.toml", "r");
	
    if (!fp) {
        error("cannot open emulatorConfig.toml - ", strerror(errno));
    }
    
    // Root table 
    toml_table_t* config = toml_parse_file(fp, errbuf, sizeof(errbuf));
    fclose(fp);
   	if (!config){
   		error("cannot parse emulatorConfig.toml - ", errbuf);
   	}
   	
    /*
    	Traverse to [mem_map] table
    */
 	toml_table_t* mem_map = toml_table_in(config, "mem_map");
 	if (!mem_map){
 		error("missing [mem_map]", "");
 	} 
 	
    /*
    	Extract values from memory map
    */
    
    // flash address
    toml_datum_t flash_addr = toml_int_in(mem_map, "flash_addr");
    if (!flash_addr.ok){
    	error("Cannot read mem_map.flash_addr", "");
    }
    FLASH_ADDR = (uint32_t)flash_addr.u.i;   // Get integer from union  
    
    // flash size
    toml_datum_t flash_size = toml_int_in(mem_map, "flash_size");
    if (!flash_size.ok){
    	error("Cannot read mem_map.flash_size", "");
    }
    FLASH_SIZE = (uint32_t)flash_size.u.i;     
    
    // sram addr
    toml_datum_t sram_addr = toml_int_in(mem_map, "sram_addr");
    if (!sram_addr.ok){
    	error("Cannot read mem_map.sram_addr", "");
    }
    SRAM_ADDR = (uint32_t)sram_addr.u.i;   
    
    // sram size
    toml_datum_t sram_size = toml_int_in(mem_map, "sram_size");
    if (!sram_size.ok){
    	error("Cannot read mem_map.sram_size", "");
    }
    SRAM_SIZE = (uint32_t)sram_size.u.i;    
    
    /*
    	Done reading general memory map information
    	Traverse to [mem_map.mmio] table
    */
    
	// mmio == mem_map.mmio
 	toml_table_t* mmio = toml_table_in(mem_map, "mmio");
 	if (!mmio){
 		error("missing [mem_map.mmio]", "");
 	}
    
    // mmio start
    toml_datum_t mmio_start = toml_int_in(mmio, "mmio_start");
    if (!mmio_start.ok){
    	error("Cannot read mmio.mmio_start", "");
    }
    MMIO_START = (uint32_t)mmio_start.u.i; 
    
    // mmio size
    toml_datum_t mmio_size = toml_int_in(mmio, "mmio_size");
    if (!mmio_size.ok){
    	error("Cannot read mmio.mmio_size", "");
    }
    MMIO_SIZE = (uint32_t)mmio_size.u.i;  
       
    /*
    	Done reading mmio information
    	Traverse to [firmware] table
    */
    
	
 	toml_table_t* firmware = toml_table_in(config, "firmware");
 	if (!firmware){
 		error("missing [firmware]", "");
 	} 
 	  
 	// Traverse to [firmware.code]
 	toml_table_t* code = toml_table_in(firmware, "code");
 	if (!code){
 		error("missing [firmware.code]", "");
 	}  
 	 
 	// code address
    toml_datum_t code_addr = toml_int_in(code, "code_addr");
    if (!code_addr.ok){
    	error("Cannot read code.code_addr", "");
    }
    CODE_ADDR = (uint32_t)code_addr.u.i; 
 	
    // NOTE: code size currently determined by file size at the moment
    /*
    toml_datum_t code_size = toml_int_in(code, "code_size");
    if (!code_size.ok){
    	error("Cannot read code.code_size", "");
    }
    CODE_SIZE = (uint32_t)code_size.u.i; 
    */ 
    	
 	// Traverse to [firmware.data]
 	toml_table_t* data = toml_table_in(firmware, "data");
 	if (!code){
 		error("missing [firmware.data]", "");
 	}      	
    	
 	// data address
    toml_datum_t data_addr = toml_int_in(data, "data_addr");
    if (!data_addr.ok){
    	error("Cannot read data.data_addr", "");
    }
    DATA_ADDR = (uint32_t)data_addr.u.i; 
 	
    // NOTE: data size currently determined by file size at the moment
    /*
    toml_datum_t data_size = toml_int_in(data, "data_size");
    if (!data_size.ok){
    	error("Cannot read data.data_size", "");
    }
    DATA_SIZE = (uint32_t)data_size.u.i; 
    */     	
    
 	// Traverse to [firmware.execution]
 	toml_table_t* execution = toml_table_in(firmware, "execution");
 	if (!execution){
 		error("missing [firmware.execution]", "");
 	}        	
    	
 	// entry point
    toml_datum_t entry = toml_int_in(execution, "entry");
    if (!entry.ok){
    	error("Cannot read execution.entry", "");
    }
    START = (uint32_t)entry.u.i; 
    
 	// end of execution
    toml_datum_t end = toml_int_in(execution, "end");
    if (!end.ok){
    	error("Cannot read execution.end", "");
    }
    END = (uint32_t)end.u.i;         	
    
    
    	            
    /*
    	Free Memory for the file
    */
    toml_free(config);
    
}



