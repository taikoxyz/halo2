.PHONY: default brecht scroll

default: brecht scroll

brecht:
	FFT=brecht RUST_LOG=info MEASURE=1 DEGREE=20 time cargo test --release -- --nocapture test_fft

scroll:
	FFT=scroll RUST_LOG=info MEASURE=1 DEGREE=20 time cargo test --release -- --nocapture test_fft
