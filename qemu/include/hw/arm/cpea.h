/*
    Created by Austin Parkes.
*/

#ifndef CPEA_H_
#define CPEA_H_

#include "cpea/cortexm-mcu.h"
#include "hw/boards.h"

// TODO: Could move emulatorConfig.h here?

/* 
    Attempt to contain ALL the board configurations the user might need to provide
    except for MMIO.
*/
typedef struct CP_board_configs {

    CortexMCoreCapabilities CP_core;
    CortexMCapabilities CP_mem;   

} CP_config;

#endif /* CPEA_H_ */
