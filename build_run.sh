cargo build
mv ./target/release/libdinfo.a ./
gcc -g -O0 -o test src/test.c -L./target/debug -ldinfo
RUST_BACKTRACE=1 ./test
