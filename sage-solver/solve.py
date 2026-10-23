#!/usr/bin/env python3
"""Google CTF 2024 - Rusty School: canonical solver.

Reverses the 12-round 4-branch Feistel cipher over 60-byte records
(48-byte ciphertext + 12-byte round-key state) and writes the plaintext.
"""

import argparse
import hashlib
import multiprocessing
import os
import struct
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed

from sage.all import *

# Primo P de 96 bits do desafio
P = 79160129948973046149879599747

def p16(x):
    return struct.pack("<H", x)

def u16(x):
    return struct.unpack("<H", x)[0]

def xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b)
    return bytes([x ^ y for x, y in zip(a, b)])

def derive(seed: bytes, *, m: int) -> bytes:
    assert len(seed) == 12
    arr = [u16(seed[i * 2 : i * 2 + 2]) for i in range(6)]
    out = []
    for i in range(6):
        key = 0
        c0, c1 = arr[(i + 2 * m) % 6], arr[(i + 2 * m + 1) % 6]
        while c0 and c1:
            key ^= c0 & -(c1 & 1)
            v17 = (c0 << 1) ^ 0x2B
            if (c0 & 0x8000) == 0:
                v17 = c0 << 1
            c0 = v17 & 0xFFFF
            c1 >>= 1
        out.append(arr[(i + 4 + m) % 6] ^ key)
    return b"".join(p16(x) for x in out)

# Inicialização do corpo finito GF(2^16) com polinômio redutor 0x2B
R = PolynomialRing(GF(2), names=('x',))
(x,) = R._first_ngens(1)
irreducible_poly = x**16 + x**5 + x**3 + x + 1
F = GF(2**16, modulus=irreducible_poly, name='a')

def solve_(solve_for, m):
    F_solve_for = [F.from_integer(int(val)) for val in solve_for]
    G = PolynomialRing(F, names=('a0', 'a1', 'a2', 'a3', 'a4', 'a5'))
    a0, a1, a2, a3, a4, a5 = G.gens()

    if m == 0:
        eqs = [
            a0 * a1 + a4 - F_solve_for[0],
            a1 * a2 + a5 - F_solve_for[1],
            a2 * a3 + a0 - F_solve_for[2],
            a3 * a4 + a1 - F_solve_for[3],
            a4 * a5 + a2 - F_solve_for[4],
            a5 * a0 + a3 - F_solve_for[5],
        ]
    elif m == 1:
        eqs = [
            a2 * a3 + a5 - F_solve_for[0],
            a3 * a4 + a0 - F_solve_for[1],
            a4 * a5 + a1 - F_solve_for[2],
            a5 * a0 + a2 - F_solve_for[3],
            a0 * a1 + a3 - F_solve_for[4],
            a1 * a2 + a4 - F_solve_for[5],
        ]

    my_id = Ideal(eqs)
    if my_id.dimension() != 0:
        return []

    my_variety = my_id.variety()
    solutions = [[
        variety[a0].to_integer(),
        variety[a1].to_integer(),
        variety[a2].to_integer(),
        variety[a3].to_integer(),
        variety[a4].to_integer(),
        variety[a5].to_integer()
    ] for variety in my_variety]
    return solutions

def solve2_(rv0, rv1):
    rv0_f = [F.from_integer(int(val)) for val in rv0]
    rv1_f = [F.from_integer(int(val)) for val in rv1]

    G = PolynomialRing(F, names=('a0', 'a1', 'a2', 'a3', 'a4', 'a5'))
    a0, a1, a2, a3, a4, a5 = G.gens()

    my_id = Ideal(
        a0 * a1 + a4 - rv0_f[0],
        a1 * a2 + a5 - rv0_f[1],
        a2 * a3 + a0 - rv0_f[2],
        a3 * a4 + a1 - rv0_f[3],
        a4 * a5 + a2 - rv0_f[4],
        a5 * a0 + a3 - rv0_f[5],
        a2 * a3 + a5 - rv1_f[0],
        a3 * a4 + a0 - rv1_f[1],
        a4 * a5 + a1 - rv1_f[2],
        a5 * a0 + a2 - rv1_f[3],
        a0 * a1 + a3 - rv1_f[4],
        a1 * a2 + a4 - rv1_f[5],
    )
    if my_id.dimension() != 0:
        return []

    my_variety = my_id.variety()
    solutions = [[
        variety[a0].to_integer(),
        variety[a1].to_integer(),
        variety[a2].to_integer(),
        variety[a3].to_integer(),
        variety[a4].to_integer(),
        variety[a5].to_integer()
    ] for variety in my_variety]
    return solutions

def solve(rv, m):
    possible_solution = solve_([u16(rv[i * 2 : i * 2 + 2]) for i in range(6)], m)
    return [b"".join(p16(x) for x in y) for y in possible_solution]

def solve2(rv0, rv1):
    possible_solution = solve2_([u16(rv0[i * 2 : i * 2 + 2]) for i in range(6)], [u16(rv1[i * 2 : i * 2 + 2]) for i in range(6)])
    return [b"".join(p16(x) for x in y) for y in possible_solution]

def to_int(x):
    return int.from_bytes(x, "little")

N_ROUNDS = 12

def do_one_round(output, rv0, rv1, n):
    shits = []
    b2, cb1, bs, cb2 = output[:12], output[12:24], output[24:36], output[36:48]
    b1 = xor(cb2, hashlib.sha1(rv1 + b2).digest()[:12])
    b0 = xor(cb1, hashlib.md5(rv0 + b2).digest()[:12])
    b3 = (((((to_int(bs) - pow(to_int(b2), to_int(b1), P) + P) % P) * pow(to_int(b0), -1, P)) % P - to_int(b1) + P) % P).to_bytes(12, "little")

    for OLD_rv0 in solve2(rv0, rv1):
        if n == N_ROUNDS - 1:
            return [(b"".join([b0, b1, b2, b3]), OLD_rv0, b'', n + 1)]
        for OLDEST_rv0 in solve(OLD_rv0, m=0):
            OLD_rv1 = derive(OLDEST_rv0, m=1)
            shits.append((b"".join([b0, b1, b2, b3]), OLD_rv0, OLD_rv1))
    return shits

def decrypt_block(output):
    assert len(output) == 60
    POSSIBLE_OUTPUTS = []
    rv1 = output[48:60]
    for pot_old_rv0 in solve(rv1, m=1):
        POSSIBLE_OUTPUTS.append((output[:48], derive(pot_old_rv0, m=0), rv1))

    for n in range(N_ROUNDS):
        POSSIBLE_OLD_INPUTS = []
        for out_data, rv0_cur, rv1_cur in POSSIBLE_OUTPUTS:
            POSSIBLE_OLD_INPUTS.extend(do_one_round(out_data, rv0_cur, rv1_cur, n))

        POSSIBLE_OLD_INPUTS = list(set(POSSIBLE_OLD_INPUTS))
        POSSIBLE_OUTPUTS = POSSIBLE_OLD_INPUTS

    for orig_input, _, _, _ in POSSIBLE_OLD_INPUTS:
        if all((c >= 0x20 and c < 0x7f) or c in [0xa, 0xd, 0x1] for c in orig_input):
            if orig_input.endswith(b'\x01'):
                orig_input = orig_input[:orig_input.find(b'\x01')]
            return orig_input
    return b''


def main():
    parser = argparse.ArgumentParser(description="Rusty School solver")
    parser.add_argument(
        "input",
        nargs="?",
        default="attachments/flag.txt.encrypted",
        help="60-byte-record encrypted input (default: attachments/flag.txt.encrypted)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="flag-sage.txt",
        help="plaintext output (default: flag-sage.txt)",
    )
    parser.add_argument(
        "-j",
        "--workers",
        type=int,
        default=os.cpu_count() or 1,
        help="worker processes (default: CPU count)",
    )
    args = parser.parse_args()

    with open(args.input, "rb") as fp:
        data = fp.read()

    if not data or len(data) % 60 != 0:
        sys.exit(f"error: {args.input} is not a non-empty multiple of 60 bytes")

    blocks = [data[i : i + 60] for i in range(0, len(data), 60)]
    print(f"[+] {len(blocks)} blocks ({len(data)} bytes) from {args.input}")

    started = time.time()
    first = decrypt_block(blocks[0])
    if not first:
        sys.exit("error: block 0 failed to decrypt")
    print(f"[+] block 0 OK ({len(first)} bytes): {first[:48]!r}")

    results = [None] * len(blocks)
    failures = []
    workers = max(1, args.workers)

    # spawn avoids Sage/Pexpect fork cleanup issues; the script guard keeps
    # child imports from re-running main().
    ctx = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as executor:
        futures = {
            executor.submit(decrypt_block, block): idx
            for idx, block in enumerate(blocks)
        }
        completed = 0
        for future in as_completed(futures):
            idx = futures[future]
            completed += 1
            try:
                result = future.result()
            except Exception as exc:
                failures.append((idx, repr(exc)))
            else:
                if result:
                    results[idx] = result
                else:
                    failures.append((idx, "empty result"))
            print(f"\r[+] {completed}/{len(blocks)} blocks", end="", flush=True)
    print()

    if failures:
        print(f"[-] {len(failures)} block(s) failed: {failures[:10]}", file=sys.stderr)
        sys.exit(1)

    plaintext = b"".join(results)
    out_dir = os.path.dirname(args.output)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.output, "wb") as fp:
        fp.write(plaintext)

    elapsed = time.time() - started
    print(f"[+] wrote {len(plaintext)} bytes to {args.output}")
    print(f"[+] md5 {hashlib.md5(plaintext).hexdigest()}")
    print(f"[+] elapsed {elapsed:.1f}s with {workers} worker(s)")


if __name__ == "__main__":
    main()
