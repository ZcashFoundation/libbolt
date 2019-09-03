package _go

// #cgo darwin CFLAGS: -D LIBSOLV_INTERNAL -I /Library/Developer/CommandLineTools/usr/include/c++/v1 -I ../include -D LD_LIBRARY_PATH=./target/release/
// #cgo darwin LDFLAGS: -L ./target/release/ -llibbolt
// #include <libbolt.h>
import "C"

func main() {
	C.ffishim_bidirectional_channel_setup("testChannel", 0)
}