/*
    The UART module(s) here mostly represents that of the FRDM-K64 UART
*/

#define SET_BIT(reg, k)     (reg |= (1<<k))
#define CHECK_BIT(reg, k)   (reg & (1<<k))
#define CLEAR_BIT(reg, k)   (reg &= ~(1<<k))

typedef struct UART0 {

    // K64 registers
    volatile uint8_t *CR2;     /* 4006_A003 */
    volatile uint8_t *SR1;     /* 4006_A004 */
    volatile uint8_t *DR;      /* 4006_A007 */
    volatile uint8_t *CR7;     /* 4006_A015 */
    
    // Extra registers for additional testing
    volatile uint8_t *CRen;    // CR which can disable an interrupt
    volatile uint8_t *CRdis;   // CR which can disable an interrupt   
     
        
} UART0regs;

// CLI states
enum State {
    IDLE,
    PROMPT,
    RXINTR
};

// Set 'size' bytes in 'src' to 'c'
void cp_memset(char *src, int c, int size);

// Compare 'n' bytes of two strings
int cp_strncmp(const char *str1, const char *str2, int n);

// Print a string over UART //TODO: Can add a DR argument in future
void print(const char *s);

// Print a character over UART
void print_char(uint8_t c);

// Prints the command the user entered
void print_cmd(void);

// Enable all ISRs in NVIC;
void enable_irqs(void);
