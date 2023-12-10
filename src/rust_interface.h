// rust_interface.h

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// MyStructの定義。フィールドはRustのMyStructと一致させる必要があります。
typedef struct {
    int64_t num;
} MyStruct;

// Rustの関数のプロトタイプ
extern MyStruct* get_array();
extern MyStruct* get_array_element(MyStruct* array, size_t index);
extern void free_array(MyStruct* array);
