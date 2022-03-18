#include <stdio.h>

volatile uint32_t * const UARTTDR = (uint32_t *)0x4006a007; 

// Print a string over UART
void print(const char *s);

int main(void){
        
    print("Welcome to CPEA!\n");            

    return 0;

}

void print(const char *s){
    while (*s != '\0'){
        *UARTTDR = (uint32_t)(*s);
        s++;
    }
}
