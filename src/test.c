#include "test.h"
#include <stdio.h>

int main() {
    // Rustのcreate_map関数を呼び出す
    void* map = get_func2args("/Users/jp31281/call-tracer/dinfo/samples/hello");

    size_t len = get_arg_count(map, "callee");
    printf("count of args in callee is %zu\n", len);

    for (int i = 0; i < len; ++i) {
        printf("=== %d th arg ===\n", i+1);
        Arg arg = get_ith_arg(map, "callee", i);

        printf("name: %s\n", arg.name);
        printf("bytes_cnt: %llu\n", arg.bytes_cnt);
        printf("location: %lld\n", arg.location);
        printf("type_name: %s\n", arg.type_name);
        printf("\n");
    }

    // Rustのfree_map関数を呼び出す
//    free_map(map);

    return 0;
}
