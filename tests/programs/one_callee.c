#include<stdio.h>
#include<stdlib.h>


void callee(int* ptr) {
    free(ptr);
}


int main() {
    int* ptr = (int*) malloc(sizeof(int));
    int* ptr2 = ptr;
    *ptr2 = 4;
    int c = getchar();
    if (c == 65) {
        ptr2 = (int*) malloc(sizeof(int)); 
    }
    free(ptr2);
    callee(ptr2);

    return 0;
}

