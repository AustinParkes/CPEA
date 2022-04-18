#include "cpea/callbacks.h"


const struct IOfuncs emulateIO[] = {
/*  {DRwrite, CRwrite, SRwrite, DRread, CRread, SRread}   */
    {NULL, NULL, NULL, NULL, NULL, NULL},
    {UARTDR_write, UARTCR_write, UARTSR_write, UARTDR_read, NULL, NULL}
        
};
