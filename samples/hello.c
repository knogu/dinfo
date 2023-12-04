#include <stdio.h>

void callee() {
    printf("Hello from callee\n");
}

int main() {
    callee();
    printf("hello\n");
}
