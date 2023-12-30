#include "test.h"
#include <stdio.h>

void dump_func(void* map, uintptr_t func_addr) {
    printf("funcname: %s\n", get_funcname(map, func_addr));
    size_t len = get_arg_cnt_from_func_addr(map, func_addr);

    for (int i = 0; i < len; i++) {
        Arg arg = get_ith_arg_from_func_addr(map, func_addr, i);
        if (arg.is_arg) {
            printf("=== %d th arg ===\n", i+1);
        } else {
            printf("=== %d th member ===\n", i+1);
        }

        printf("name: %s\n", arg.name);
        printf("bytes_cnt: %llu\n", arg.bytes_cnt);
        printf("location: %lld\n", arg.location);
        printf("typ: %s\n", arg.typ->name);
        if (arg.typ->pointed) {
            printf("pointed: %s\n", arg.typ->pointed->name);
        }
        printf("struct?\n");
        if (arg.typ->struct_first_field) {
            printf("first: %s\n", arg.typ->struct_first_field->name);
            printf("second: %s\n", arg.typ->struct_first_field->struct_next_field->name);
        }
        printf("\n");
    }
}

int main() {
    printf("hihi");
    void* map = get_addr2func("/Users/jp31281/call-tracer/dinfo/samples/sample");
    printf("!");
    void* ptr = 0x0001189;

    dump_func(map, ptr);

//    map = get_addr2func("/Users/jp31281/call-tracer/dinfo/samples/enum");
//    ptr = 0x00001149;
//
//    dump_func(map, ptr);

    return 0;
}
