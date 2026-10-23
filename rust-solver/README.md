# rustyschool — solver

Recovers the plaintext of `attachments/flag.txt.encrypted` (7980 B = 133
blocks) without the encrypter's random nonces.

From the repository root:

```
cargo run --release --manifest-path rust-solver/Cargo.toml -- \
  --decrypt attachments/flag.txt.encrypted
# -> flag-rust.txt
```

Override the output path with `-o`/`--output`:

```
cargo run --release --manifest-path rust-solver/Cargo.toml -- \
  --decrypt attachments/flag.txt.encrypted -o /tmp/flag.txt
```

## Encrypter mode

The reconstructed encrypter is also runnable:

```bash
cargo run --release --manifest-path rust-solver/Cargo.toml -- <file>
# -> <file>.encrypted
```

It draws a fresh random nonce for each block, so the ciphertext differs between
runs.

## Provenance

`src/encrypt.rs` is a reconstruction of the original challenge encrypter made
from the Rust binary in Ghidra. It is not part of the decryption path; it is a
test oracle. With a nonce pinned during development it reproduces the original
binary's output byte-for-byte, which is what lets the Rust solver round-trip its
inversions against the real cipher. The current CLI always uses a random nonce.

## Cipher recap

Each 48-byte block runs 12 Feistel rounds. Round `r` uses nonce `N_r`, with
`N_0` drawn at random and `N_{r+1} = LE(A(N_r))`; the block emits the 48-byte
state followed by `LE(B(N_11))`, where for a 6-word nonce `s`

```
A(s)[i] = s[i]*s[i+1] ^ s[i+4]          B(s)[i] = s[i+2]*s[i+3] ^ s[i+5]   (indices mod 6)
```

over GF(2^16) with `y^16 + y^5 + y^3 + y + 1`. With `M0..M3` the little-endian
integers of the four state words and `ks_a`/`ks_b` the little-endian bytes of
`A`/`B` of the round nonce:

```
T   = ((M2^M1 mod p) + M0*(M3 + M1)) mod p        p = 79160129948973046149879599747
out = [ w2, w0 ^ MD5(ks_a || w2), LE12(T), w1 ^ SHA1(ks_b || w2), ks_b ]
```

So a round is inverted from the outgoing state plus that round's nonce: `w2`
and `ks_b` read straight off, both digests are recomputed, and `T` solves for
`M3` linearly. `M0 ≡ 0 (mod p)` makes the round lossy — no implementation can
recover `M3` there.

The only unknown is the nonce chain, entered through `B(N_11)` (the emitted
tail) and walked back eleven times through `A`.

## Inverting `A`/`B` — the two things that matter

**1. One guessed word is enough.** Both systems are quadratic, but each equation
is linear in its own word once products are pinned, so all six words fall out as
rational functions of one guess. The two unused equations become univariate
polynomials whose common roots are the consistent guesses.

**2. Do not scan all 2^16 guesses.** `res_t(p1, p2)` is a polynomial in the
guessed word and vanishes whenever a common root exists, so its roots contain
every consistent guess. It has small degree, so `candidate_guesses` evaluates it
at a handful of guesses, Lagrange-interpolates it, checks the interpolant
against held-out points, and root-finds. One inversion went from 350 ms to
~310 µs (≈1100×), cross-checked while developing against an exhaustive 2^16
scan on random targets (0 mismatches in 24 cases); that scan has since been
deleted.

Branching is ~1–2 per round with plenty of dead ends, so a DFS over the chain
that tests the round-0 plaintext against printable ASCII (plus CR/LF and the
`0x01` read padding) finds the answer after a few dozen inversions. Overall:
**133 blocks in roughly 1–2 s**, parallelised across cores.

## Bugs found and fixed

* `gf16::split_linear` recursed on `pdivmod(g, d).1` — the *remainder*, always
  zero — so Cantor–Zassenhaus silently dropped every root outside the first
  split factor. Root finding only appeared to work because most inputs were
  degree ≤ 2 and hit the base case. Fixed to use the quotient `.0`.
* The chain walk called `invert_rkey` on `A(candidate)` instead of on
  `candidate`, stepping the chain one level off and producing garbage that the
  old buffer-fallback returned as if it were the plaintext. Both fixed.

## Verification

* `encrypt.rs` reproduces the binary's output byte-exactly for a pinned nonce.
* End to end on a real target-encrypted file: 47 bytes of `A` recovered
  byte-identical in 25 ms against the binary's own ciphertext.
* Re-decrypting the 133-block flag reproduces the same 6359 bytes
  (md5 `468a48469137692c853e3c665dc49a23`).
* The round inversion was additionally round-tripped against the encrypter for
  0/47/48/96/200-byte inputs while the code still accepted known nonces.
* All 133 blocks of the flag independently pass the printable-ASCII filter
  (random 48-byte data would do so with probability ≈ 10^-22).

`flag-rust.txt` is 6359 bytes of ASCII art: a `figlet` *colossal* banner
spelling the flag. The art is the flag file's actual content; decode it with
`figlet -f colossal` or read it as rendered.
