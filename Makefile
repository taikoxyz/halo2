# Use branch `einar/fft` from `https://github.com/einar-taiko/halo2`
brecht:
	RUST_LOG=info MEASURE=1 DEGREE=30 time cargo test --release -- --nocapture test_fft

# Use branch `test_ftt_opt` from `https://github.com/scroll-tech/halo2.git`
scroll:
	@echo 'Remeber to checkout the right branch: `
	@echo 'git checkout test_ftt_opt'
	cargo test --release --package halo2_proofs --lib domain::test_fft  -- --nocapture
