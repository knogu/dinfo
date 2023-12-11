// main.c

#include "test.h"
#include <string.h>
#include <stdio.h>

int main() {
    // Rustのcreate_map関数を呼び出す
    void* map = get_func2args("/Users/jp31281/call-tracer/dinfo/samples/hello");

    size_t len = get_vec_len(map, "callee");
    printf("count of args in callee is %zu\n", len);

    // Rustのget_vec_len関数を呼び出す
//    size_t len = get_vec_len(map, key_array, key_len);
//    printf("The length of the vector is %zu\n", len);

    // Rustのfree_map関数を呼び出す
//    free_map(map);

    return 0;
}
