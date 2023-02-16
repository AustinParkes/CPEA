#include "cpea/handlers.h"


const struct IOhandlers emulateIO[] = {
/*  {DRwrite, CRwrite, SRwrite, DRread, CRread, SRread}   */
    {NULL, NULL, NULL, NULL, NULL, NULL},
    {UARTDR_write, UARTCR_write, UARTSR_write, UARTDR_read, NULL, NULL}
        
};
