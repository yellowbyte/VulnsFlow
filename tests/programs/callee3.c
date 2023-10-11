#include<stdio.h>
#include<stdlib.h>


int* callee() {
    char* ptr = (int*) malloc(sizeof(int));
    char* ptr2 = ptr;
    int c = getchar();
    free(ptr);
    int e = getchar();
    return ptr;
}


int main() {

    int c = getchar();
    char* ptr2;
    if (c == 65) {
        ptr2 = (char*) malloc(sizeof(int)); 
    }

    char* cptr = callee(ptr2);
    free(ptr2);
    free(cptr);

    return 0;
}

