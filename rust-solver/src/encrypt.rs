//! Reconstruction of the challenge encrypter from the original Rust binary
//! (Ghidra). Kept as a test oracle; the decrypter does not depend on it.

use std::env;
use std::fs;
use std::io;
use std::str::FromStr;

use itertools::Itertools;
use rand::Rng;
use num_bigint::BigUint;
use sha1::{Digest, Sha1};

/// Length of the random nonce buffer: the caller passes `Range { start: 0, end: 12 }`.
pub const NONCE_LEN: usize = 12;

/// Entry point for the encrypter.
///
/// Mirrors `rustyschool <filename_to_encrypt>`:
/// reads the named file and writes `<filename_to_encrypt>.encrypted`.
pub fn run() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("usage: {} <filename_to_encrypt>", args[0]);
        return Ok(());
    }

    let in_path = &args[1];
    let out_path = format!("{}.encrypted", in_path);

    println!("Loading file to encrypt: {}", in_path);
    let plaintext = fs::read(in_path)?;

    let ciphertext = encrypt(&plaintext);

    fs::write(&out_path, ciphertext)?;
    println!("Encryption completed :)");

    Ok(())
}

/// `main`'s `generate_nonce`: one random byte per element, chained as
/// `(0..len).map(|_| rng.gen_range(0..=0xff)).collect()` over the thread-local RNG.
///
/// The range is the full `RangeInclusive<u8>`, so rand takes its `range == 0`
/// fast path and this lowers to exactly `rng.gen::<u8>()` (low byte of `next_u32`).
pub fn generate_nonce(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| rng.gen_range(0..=0xffu8)).collect()
}

/// Multiply in GF(2^16) with reduction polynomial `x^16 + x^5 + x^3 + x + 1`
/// (truncated low half `0x2b`). Shift-and-xor, one bit of `b` per round.
pub(crate) fn gf16_mul(mut a: u16, mut b: u16) -> u16 {
    let mut p = 0u16;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = if a & 0x8000 != 0 { (a << 1) ^ 0x2b } else { a << 1 };
        b >>= 1;
    }
    p
}

/// `derive_subnonce_1`: `(0..6).map(|i| gfmul(n[i], n[i+1]) ^ n[i+4]).collect()`,
/// all indices taken mod 6.
pub fn derive_subnonce_1(nonce: &[u16]) -> Vec<u16> {
    (0..6)
        .map(|i| gf16_mul(nonce[i], nonce[(i + 1) % 6]) ^ nonce[(i + 4) % 6])
        .collect()
}

/// `derive_subnonce_2`: `(0..6).map(|i| gfmul(n[i+2], n[i+3]) ^ n[i+5]).collect()`,
/// all indices taken mod 6.
pub fn derive_subnonce_2(nonce: &[u16]) -> Vec<u16> {
    (0..6)
        .map(|i| gf16_mul(nonce[(i + 2) % 6], nonce[(i + 3) % 6]) ^ nonce[(i + 5) % 6])
        .collect()
}

/// The number of rounds each 48-byte block is put through (`cd46: inc %r12d`,
/// gated by `if (iVar31 == 0xc)`).
const ROUNDS: usize = 12;

pub fn encrypt(plaintext: &[u8]) -> Vec<u8> {
    let mut plaintext_blocks = plaintext
        .chunks(48)
        .map(|chunk| {
            chunk
                .iter()
                .cloned()
                .chain(std::iter::repeat(1))
                .take(48)
                .collect_vec()
        })
        .collect_vec();

    if plaintext.len() % 48 == 0 {
        plaintext_blocks.push(vec![1u8; 48]);
    }

    let mut ciphertext = Vec::with_capacity(plaintext_blocks.len() * 60);

    for i in 0..plaintext_blocks.len() {
        'block: loop {
            let mut plaintext_chunks = plaintext_blocks[i]
                .chunks(12)
                .map(|chunk| chunk.to_vec())
                .collect_vec();
            let mut _nonce = generate_nonce(NONCE_LEN);
            let mut key_word: Vec<u8> = Vec::new();

            for _round in 0..ROUNDS {
                let nonce_words = _nonce.chunks(2).map(|chunk| u16::from_le_bytes(*chunk.as_array::<2>().unwrap())).collect_vec();
                let subnonce_1 = derive_subnonce_1(&nonce_words);
                let subnonce_2 = derive_subnonce_2(&nonce_words);

                let subnonce_1 = subnonce_1.iter().map(|word| word.to_le_bytes().to_vec()).concat();
                let subnonce_2 = subnonce_2.iter().map(|word| word.to_le_bytes().to_vec()).concat();

                let plaintext_bigint = plaintext_chunks.iter().map(|bytes| BigUint::from_bytes_le(bytes)).collect_vec();

                let p = BigUint::from_str("79160129948973046149879599747").unwrap();

                // `M3 >= p` -> `break` out of the round loop, which discards the
                // block and jumps back to the nonce draw.
                if plaintext_bigint[3] >= p {
                    continue 'block;
                }

                // T = ((M2^M1 mod p) + M0*(M3 + M1)) mod p
                let t = (plaintext_bigint[2].modpow(&plaintext_bigint[1], &p)
                    + &plaintext_bigint[0] * (&plaintext_bigint[3] + &plaintext_bigint[1]))
                    % &p;

                // `to_bitwise_digits_le(.., 8)` then zero-filled up to 0xc.
                let mut out_2 = t.to_bytes_le();
                out_2.resize(12, 0);

                // The inlined `md5::compress::soft::compress` call is a plain
                // MD5 over `subnonce_1 || w2`.
                let mut md5_input = subnonce_1.clone();
                md5_input.extend_from_slice(&plaintext_chunks[2]);
                let md5_out = md5::compute(&md5_input);

                // Likewise `sha1::compress::compress` is a plain SHA1 over
                // `subnonce_2 || w2`.
                let mut sha1_input = subnonce_2.clone();
                sha1_input.extend_from_slice(&plaintext_chunks[2]);
                let sha1_out = Sha1::digest(&sha1_input);

                // Emitted word order is (w2, w0^md5, T, w1^sha1, subnonce_2).
                let out_0 = plaintext_chunks[2].clone();
                let out_1 = plaintext_chunks[0]
                    .iter()
                    .zip(md5_out.iter())
                    .map(|(a, b)| a ^ b)
                    .collect_vec();
                let out_3 = plaintext_chunks[1]
                    .iter()
                    .zip(sha1_out.iter())
                    .map(|(a, b)| a ^ b)
                    .collect_vec();

                key_word = subnonce_2;
                plaintext_chunks = vec![out_0, out_1, out_2, out_3];
                _nonce = subnonce_1;
            }

            ciphertext.extend(plaintext_chunks.iter().flatten());
            ciphertext.extend(&key_word);
            break;
        }
    }

    ciphertext
}
