#[repr(C)]
pub struct MyStruct {
    num: u64,
}

const N: usize = 3; // 配列の長さ

#[no_mangle]
pub extern "C" fn get_array() -> *mut [MyStruct; N] {
    let a = Box::new([
        MyStruct { num: 10 },
        MyStruct { num: 20 },
        MyStruct { num: 30 },
    ]);
    Box::into_raw(a)
}

#[no_mangle]
pub extern "C" fn get_array_element(a: *mut [MyStruct; N], index: usize) -> *const MyStruct {
    let a = unsafe { &*a };
    &a[index]
}

#[no_mangle]
pub extern "C" fn free_array(a: *mut [MyStruct; N]) {
    unsafe { Box::from_raw(a); }
}
