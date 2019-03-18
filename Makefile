.PHONY: all debug bench test update doc clean

all:
	export RUSTFLAGS=-Awarnings
	cargo +nightly build
	cargo +nightly run --example bolt_test

debug:
	export RUST_BACKTRACE=1 
	cargo +nightly build
	cargo +nightly run --example bolt_test

release:
	cargo +nightly build --release
	cargo +nightly run --release --example bolt_test

bench:
	cargo +nightly bench

test:
	# runs the unit test suite
	cargo +nightly test --release #-- --nocapture

update:
	# updates local git repos (for forked bn lib)
	cargo +nightly update

doc:
	# generates the documentation
	cargo +nightly doc

pythontests:
	cargo +nightly build
	python src/main.py

cpptests:
	cargo +nightly build
	g++ src/main.cpp -L ./target/debug/ -lbolt -o cpp_test
	LD_LIBRARY_PATH=./target/debug/ ./cpp_test
	rm cpp_test

clean:
	cargo +nightly clean
