# Setup

The repository has two independent solvers:

* **SageMath:** `sage-solver/solve.py`
* **Rust:** `rust-solver/`

Both read `attachments/flag.txt.encrypted` and produce the 6,359-byte flag.

## SageMath 10.x

The SageMath solver uses `from_integer()`/`to_integer()`, available from
SageMath 10. Older 9.x releases do not provide these methods.

Use any SageMath 10.x installation: official binaries, conda-forge, mamba, or
a distribution package that provides SageMath 10.x. For example, with Conda:

```bash
conda create -n sage -c conda-forge 'sage>=10'
conda activate sage
```

Run from the repository root:

```bash
python sage-solver/solve.py attachments/flag.txt.encrypted
# -> flag-sage.txt
```

If your installation does not expose `python` on `PATH`, invoke the
environment's interpreter directly:

```bash
/path/to/sage/bin/python sage-solver/solve.py attachments/flag.txt.encrypted
```

Verify the version:

```bash
sage --version   # must be 10.x
```

### Common error

```text
AttributeError: 'FiniteField_ntl_gf2e_with_category'
                object has no attribute 'from_integer'
```

An older SageMath is being used. Check `sage --version` and select a SageMath
10.x environment.

Some Sage launchers do not accept `sage -python`; use the environment's
`python` instead.

## Rust

Requires a Rust toolchain with edition 2024 support (`cargo`/`rustc`).

```bash
cargo run --release --manifest-path rust-solver/Cargo.toml -- \
  --decrypt attachments/flag.txt.encrypted
# -> flag-rust.txt
```

See `rust-solver/README.md` for the implementation details.
