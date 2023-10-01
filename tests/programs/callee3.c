#include<stdio.h>
#include<stdlib.h>


int* callee() {
    int* ptr = (int*) malloc(sizeof(int));
    int* ptr2 = ptr;
    int c = getchar();
    free(ptr);
    int e = getchar();
    return ptr;
}


int main() {

    int c = getchar();
    int* ptr2;
    if (c == 65) {
        ptr2 = (int*) malloc(sizeof(int)); 
    }

    int* cptr = callee(ptr2);
    free(ptr2);
    free(cptr);

    return 0;
}

