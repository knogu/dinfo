cargo build --release
mv ./target/release/libdinfo.a ./
gcc -o test src/test.c -L. -ldinfo && RUST_BACKTRACE=1 ./test
