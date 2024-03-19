#include <stdio.h>
#include "ct_header.h"

int main(){
    unsigned char h1 = GET_HIGH_UCHAR;
    unsigned char l1 = GET_LOW_UCHAR;
    char arr[] = {1,2,3,4,5};
    arr[l1] = h1;
    if(arr[l1]){
        printf("arr[l1] aka h1 is not 0\n");
    }
    return 0;
}