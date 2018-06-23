.PHONY: all bench test update doc clean

all:
	export RUST_BACKTRACE=1
	cargo build
	cargo run

bench:
	cargo bench

test:
	# runs the unit test suite
	cargo test

update:
	# updates local git repos (for forked bn lib)
	cargo update

doc:
	# generates the documentation
	cargo doc

clean:
	cargo clean
