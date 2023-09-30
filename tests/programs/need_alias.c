#include<stdio.h>
#include<stdlib.h>


int main() {
    int* ptr = (int*) malloc(sizeof(int));
    int* ptr2 = ptr;
    *ptr2 = 4;
    int c = getchar();
    if (c == 65) {
        ptr2 = (int*) malloc(sizeof(int)); 
    }
    free(ptr2);
    puts("hello");
    free(ptr);

    return 0;
}
