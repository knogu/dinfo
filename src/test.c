#include "test.h"
#include <stdio.h>

void dump(void* map, char *name) {
    size_t len = get_arg_count(map, name);

    for (int i = 0; i < len; ++i) {
        Arg arg = get_ith_arg(map, name, i);
        if (arg.is_arg) {
            printf("=== %d th arg ===\n", i+1);
        } else {
            printf("=== %d th member ===\n", i+1);
        }

        printf("name: %s\n", arg.name);
        printf("bytes_cnt: %llu\n", arg.bytes_cnt);
        printf("location: %lld\n", arg.location);
        printf("type_name: %s\n", arg.type_name);
        printf("\n");
    }
}

int main() {
    // Rustのcreate_map関数を呼び出す
    void* map = get_func2args("/Users/jp31281/call-tracer/dinfo/samples/hello");

    dump(map, "callee");
    dump(map, "Person");

    // Rustのfree_map関数を呼び出す
//    free_map(map);

    return 0;
}
