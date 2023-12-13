#include <stdio.h>
#include <stdbool.h>

struct Person {
    int age;
    bool is_man;
};

void callee(char* msg, int num, struct Person person, int* arr) {
    printf("%s", msg);
    printf("passed num is %d\n", num);
    printf("passed person is man? %d\n", person.is_man);
    for (int i = 0; i < 3; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
}

int main() {
    int arr[3] = {1, 2, 3};
    struct Person person = {20, true};
    callee("Hi from callee\n", 99, person, arr);
}