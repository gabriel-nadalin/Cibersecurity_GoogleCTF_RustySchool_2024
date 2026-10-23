# SageMath solver

Canonical SageMath implementation. It reverses the 12-round, 4-branch Feistel
cipher, resolves the GF(2^16) quadratic systems with `Ideal.variety()`, and
handles the final block's `0x01` padding.

## Requirements

* SageMath **10.x** — 9.x lacks `from_integer()`/`to_integer()`.

See `../docs/SETUP.md`.

## Usage

Activate or select your SageMath 10.x environment, then run from the
repository root:

```bash
python sage-solver/solve.py attachments/flag.txt.encrypted
# -> flag-sage.txt
```

Options:

```bash
python sage-solver/solve.py <input> -o <output> -j <workers>
```

The solver exits non-zero if any block fails; it does not silently drop
blocks. A full run is CPU-bound; raise `-j` to use more workers.

## Output

```text
[+] 133 blocks (7980 bytes) from attachments/flag.txt.encrypted
[+] block 0 OK (48 bytes): b'\n .d8888b. 88888888888 8888888888 .d888 8888888 '
...
[+] wrote 6359 bytes to flag-sage.txt
[+] md5 468a48469137692c853e3c665dc49a23
```
