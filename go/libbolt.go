package _go

// #cgo darwin CFLAGS: -I ../include -D LD_LIBRARY_PATH=../target/release 
// #cgo darwin LDFLAGS: -L ../target/release/ -lbolt
// #include <libbolt.h>
import "C"

func main() {
	C.ffishim_bidirectional_channel_setup("testChannel", 0)
}
