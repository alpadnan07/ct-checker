#include <stdio.h>
#include "ct_header.h"

int main(){
    int h1 = GET_HIGH_INT;
    h1 *= 0;
    printf("0 is %d\n",h1);
    return 0;
}