#pragma once
#define SYMBOLIC_ADDR_LOW 0xDEADBEEF
char *_symbolic_addr_low = ((char *)SYMBOLIC_ADDR_LOW);
#define SYMBOLIC_ADDR_HIGH 0xCAFEBABE
char *_symbolic_addr_high = (((char *)SYMBOLIC_ADDR_HIGH));


#define GET_LOW(t) (_symbolic_addr_low+=sizeof(t),*(t *)(_symbolic_addr_low-sizeof(t)))
// #define GET_LOW_BYTE ((char)(*((char *)(_symbolic_addr_low++))))
#define GET_LOW_CHAR (GET_LOW(char))
#define GET_LOW_UCHAR (GET_LOW(unsigned char))
#define GET_LOW_INT (GET_LOW(int))
#define GET_LOW_VOIDPTR (GET_LOW(void *))

#define GET_HIGH(t) (_symbolic_addr_high+=sizeof(t),*(t *)(_symbolic_addr_high-sizeof(t)))
// #define GET_HIGH_BYTE ((char)(*((char *)(_symbolic_addr_high++))))
#define GET_HIGH_CHAR (GET_HIGH(char))
#define GET_HIGH_UCHAR (GET_HIGH(unsigned char))
#define GET_HIGH_INT (GET_HIGH(int))
#define GET__HIGH_VOIDPTR (GET_HIGH(void *))
