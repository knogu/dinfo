// main.c

#include "test.h"


int main() {
    // Rustのget_array関数を呼び出す
    MyStruct* array = get_array();

    // Rustのget_array_element関数を呼び出す
    MyStruct* element = get_array_element(array, 0);
    printf("%lld", element->num);
    // elementを使って何かをする...

    // Rustのfree_array関数を呼び出す
    free_array(array);

    return 0;
}
