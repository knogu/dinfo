#include <stdint.h>
#include <stdlib.h>

// Argの定義。フィールドはRustのArgと一致させる必要があります。
typedef struct {
    char* name;
    int64_t location;
    char* type_name;
    uint64_t bytes_cnt;
} Arg;

// Rustの関数のプロトタイプ
extern void* get_func2args(const char* file_path);
extern size_t get_vec_len(void* map, const char* key);
//extern void free_map(void* map);
