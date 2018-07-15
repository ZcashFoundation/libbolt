.PHONY: all bench test update doc clean

all:
	export RUST_BACKTRACE=1
	cargo +nightly build
	cargo +nightly run

bench:
	cargo +nightly bench

test:
	# runs the unit test suite
	cargo +nightly test

update:
	# updates local git repos (for forked bn lib)
	cargo +nightly update

doc:
	# generates the documentation
	cargo +nightly doc

clean:
	cargo +nightly clean
