#define SET_BIT(reg, k)     (reg |= (1<<k))
#define CHECK_BIT(reg, k)   (reg & (1<<k))
#define CLEAR_BIT(reg, k)   (reg &= ~(1<<k))

typedef struct UART0 {

    volatile uint8_t *CR2;     /* 4006_A003 */
    volatile uint8_t *SR1;     /* 4006_A004 */
    volatile uint8_t *DR;      /* 4006_A007 */
    volatile uint8_t *CR7;     /* 4006_A015 */
    
    volatile uint8_t *CRen;    // CR which can disable an interrupt
    volatile uint8_t *CRdis;   // CR which can disable an interrupt   
     
        
} UART0regs;

// CLI states
enum State {
    IDLE,
    PROMPT,
    RXINTR
};



