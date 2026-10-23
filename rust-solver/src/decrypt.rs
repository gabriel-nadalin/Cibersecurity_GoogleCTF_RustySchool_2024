use std::str::FromStr;

use num_bigint::BigUint;
use sha1::{Digest, Sha1};

use crate::encrypt::{derive_subnonce_1, derive_subnonce_2};
use crate::gf16::{self, Rat};

/// Rounds per 48-byte block; mirrors the encrypter.
const ROUNDS: usize = 12;

/// The 96-bit safe prime used as the modulus.
const P: &str = "79160129948973046149879599747";

/// A 12-byte word read as six little-endian `u16`s.
fn words_le(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect()
}

/// Six `u16`s flattened back to 12 little-endian bytes.
fn bytes_le(words: &[u16]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

/// Which round-key map to invert.
#[derive(Clone, Copy)]
enum Rkey {
    /// `k_a[i] = n[i]*n[i+1] ^ n[i+4]` — becomes the next round's nonce.
    A,
    /// `k_b[i] = n[i+2]*n[i+3] ^ n[i+5]` — emitted alongside the state.
    B,
}

/// Guess word `n1` and express the rest of system `A` through `n0`, the free
/// variable `t`. Returns the two equations the propagation did not consume, or
/// `None` when a divisor vanishes identically, which puts the guess outside the
/// parametrisation's domain.
fn propagate_a(coeff: &[u16], guess: u16, t: &Rat) -> Option<([Rat; 6], gf16::Poly, gf16::Poly)> {
    let c: Vec<Rat> = coeff.iter().map(|&v| Rat::constant(v)).collect();
    let g = Rat::constant(guess);

    // A0: n4 = c0 ^ n0*n1
    let n4 = c[0].add(&t.mul(&g));
    if n4.is_zero() {
        return None;
    }
    // A3: n3 = (c3 ^ n1)/n4
    let n3 = c[3].add(&g).div(&n4);
    if n3.is_zero() {
        return None;
    }
    // A2: n2 = (c2 ^ n0)/n3
    let n2 = c[2].add(t).div(&n3);
    // A4: n5 = (c4 ^ n2)/n4
    let n5 = c[4].add(&n2).div(&n4);

    // A1: n1*n2 ^ n5 ^ c1 = 0 ; A5: n5*n0 ^ n3 ^ c5 = 0
    let p1 = g.mul(&n2).add(&n5).add(&c[1]).numerator();
    let p2 = n5.mul(t).add(&n3).add(&c[5]).numerator();

    Some(([t.clone(), g, n2, n3, n4, n5], p1, p2))
}

/// Guess word `n3` and express the rest of system `B` through `n4`.
fn propagate_b(coeff: &[u16], guess: u16, t: &Rat) -> Option<([Rat; 6], gf16::Poly, gf16::Poly)> {
    let c: Vec<Rat> = coeff.iter().map(|&v| Rat::constant(v)).collect();
    let g = Rat::constant(guess);

    // B1: n0 = c1 ^ n3*n4
    let n0 = c[1].add(&g.mul(t));
    // B3 with B0 substituted: n2 = (c3 ^ c0*n0)/(1 ^ n3*n0)
    let divisor = Rat::constant(1).add(&g.mul(&n0));
    if divisor.is_zero() {
        return None;
    }
    let n2 = c[3].add(&c[0].mul(&n0)).div(&divisor);
    // B0: n5 = c0 ^ n2*n3
    let n5 = c[0].add(&n2.mul(&g));
    // B2: n1 = c2 ^ n4*n5
    let n1 = c[2].add(&t.mul(&n5));

    // B4: n0*n1 ^ n3 ^ c4 = 0 ; B5: n1*n2 ^ n4 ^ c5 = 0
    let p1 = n0.mul(&n1).add(&g).add(&c[4]).numerator();
    let p2 = n1.mul(&n2).add(t).add(&c[5]).numerator();

    Some(([n0, n1, n2, g, t.clone(), n5], p1, p2))
}

/// Evaluate the parametrisation at `guess`, keeping only the two equations it
/// did not consume.
fn sample(coeff: &[u16], kind: Rkey, guess: u16) -> Option<([Rat; 6], gf16::Poly, gf16::Poly)> {
    let t = Rat::variable();
    match kind {
        Rkey::A => propagate_a(coeff, guess, &t),
        Rkey::B => propagate_b(coeff, guess, &t),
    }
}

/// Evaluate every word of the parametrisation at `root`.
fn rebuild(words: &[Rat; 6], root: u16) -> Option<[u16; 6]> {
    let mut out = [0u16; 6];
    for (slot, word) in out.iter_mut().zip(words) {
        *slot = gf16::eval_rat(&word.numerator(), &word.denominator(), root)?;
    }
    Some(out)
}

/// Check all six equations of the system.
fn verify(candidate: &[u16; 6], coeff: &[u16], kind: Rkey) -> bool {
    let n = candidate;
    (0..6).all(|i| {
        let lhs = match kind {
            Rkey::A => gf16::mul(n[i], n[(i + 1) % 6]) ^ n[(i + 4) % 6],
            Rkey::B => gf16::mul(n[(i + 2) % 6], n[(i + 3) % 6]) ^ n[(i + 5) % 6],
        };
        lhs == coeff[i]
    })
}

/// Every guess for which the two leftover equations share a root.
///
/// A shared root forces `res_t(p1, p2)` to vanish, and that resultant is a
/// polynomial of small degree in the guessed word, so it is recovered by
/// evaluating it at a few guesses and interpolating rather than scanning all
/// 2^16 guesses.
fn candidate_guesses(coeff: &[u16], kind: Rkey) -> Option<Vec<u16>> {
    for points in [24usize, 48, 96] {
        let pool: Vec<(u16, gf16::Poly, gf16::Poly)> = (0..=0xffffu16)
            .filter_map(|guess| sample(coeff, kind, guess).map(|(_, p1, p2)| (guess, p1, p2)))
            .take(points + 12)
            .collect();
        if pool.len() < points + 8 {
            return None;
        }

        // The generic degrees define the resultant; where either polynomial
        // drops degree the specialised resultant is a different polynomial, so
        // those points cannot serve as interpolation samples.
        let d1 = pool.iter().map(|(_, p1, _)| p1.len() - 1).max().unwrap();
        let d2 = pool.iter().map(|(_, _, p2)| p2.len() - 1).max().unwrap();
        let good: Vec<&(u16, gf16::Poly, gf16::Poly)> = pool
            .iter()
            .filter(|(_, p1, p2)| p1.len() - 1 == d1 && p2.len() - 1 == d2)
            .collect();
        if good.len() < points + 8 {
            continue;
        }

        let xs: Vec<u16> = good[..points].iter().map(|(g, _, _)| *g).collect();
        let ys: Vec<u16> = good[..points]
            .iter()
            .map(|(_, p1, p2)| gf16::resultant(p1, p2))
            .collect();
        let resultant = gf16::interpolate(&xs, &ys);
        if gf16::is_zero(&resultant) {
            continue;
        }

        // The interpolant has to reproduce the resultant at guesses it was not
        // fitted to; if it does not, it is not the resultant.
        let consistent = good[points..]
            .iter()
            .all(|(g, p1, p2)| gf16::eval(&resultant, *g) == gf16::resultant(p1, p2));
        if !consistent {
            continue;
        }

        return Some(gf16::roots(&resultant));
    }
    None
}

/// Invert one round-key map.
///
/// Both systems are quadratic, but each equation is linear in its own word once
/// the products are pinned, so guessing one word determines the other five as
/// rational functions of a second; the two unused equations then pin the guess.
/// The map is many-to-one, so every solution is returned.
fn invert_rkey(coeff: &[u16], kind: Rkey) -> Vec<[u16; 6]> {
    let mut found = Vec::new();

    for guess in candidate_guesses(coeff, kind).unwrap_or_default() {
        let Some((words, p1, p2)) = sample(coeff, kind, guess) else {
            continue;
        };

        let common = match (gf16::is_zero(&p1), gf16::is_zero(&p2)) {
            // Both equations vanish identically: every free value is a solution.
            (true, true) => vec![0, 1],
            (true, false) => p2,
            (false, true) => p1,
            (false, false) => gf16::pgcd(&p1, &p2),
        };
        if common.len() <= 1 {
            continue;
        }

        for root in gf16::roots(&common) {
            let Some(candidate) = rebuild(&words, root) else {
                continue;
            };
            if verify(&candidate, coeff, kind) {
                found.push(candidate);
            }
        }
    }

    found.sort_unstable();
    found.dedup();
    found
}

/// Invert one round, returning the four message words that entered it.
///
/// Forward, with `M0..M3` the little-endian integers of `w0..w3`,
/// `ks_a = LE(derive_subnonce_1(nonce))` and `ks_b = LE(derive_subnonce_2(nonce))`:
///
/// ```text
/// T    = ((M2^M1 mod p) + M0*(M3 + M1)) mod p
/// out  = [ w2, w0^MD5(ks_a||w2), LE12(T), w1^SHA1(ks_b||w2), ks_b ]
/// ```
///
/// `out[0]` gives `w2` back directly, which is all both digests need; `T` then
/// solves for `M3` linearly. Returns `None` when `M0 ≡ 0 (mod p)`, where the
/// product term vanishes and the round is genuinely lossy.
fn invert_round(out: &[Vec<u8>], nonce: &[u8]) -> Option<Vec<Vec<u8>>> {
    let p = BigUint::from_str(P).unwrap();

    let nonce_words = words_le(nonce);
    let w2 = out[0].clone();
    let ks_a = bytes_le(&derive_subnonce_1(&nonce_words));
    let ks_b = bytes_le(&derive_subnonce_2(&nonce_words));

    let mut md5_input = ks_a;
    md5_input.extend_from_slice(&w2);
    let md5_out = md5::compute(&md5_input);

    let mut sha1_input = ks_b;
    sha1_input.extend_from_slice(&w2);
    let sha1_out = Sha1::digest(&sha1_input);

    let w0: Vec<u8> = out[1].iter().zip(md5_out.iter()).map(|(a, b)| a ^ b).collect();
    let w1: Vec<u8> = out[3].iter().zip(sha1_out.iter()).map(|(a, b)| a ^ b).collect();

    // T = ((M2^M1 mod p) + M0*(M3 + M1)) mod p, so
    //   M3 = ((T - M2^M1) * M0^-1 - M1) mod p
    let t = BigUint::from_bytes_le(&out[2]);
    let m0 = BigUint::from_bytes_le(&w0);
    let m1 = BigUint::from_bytes_le(&w1);
    let m2 = BigUint::from_bytes_le(&w2);

    let m0_inv = (m0 % &p).modinv(&p)?;
    let m3 = ((&t + &p - m2.modpow(&m1, &p) % &p) % &p * m0_inv + &p - (m1 % &p)) % &p;

    let mut w3 = m3.to_bytes_le();
    w3.resize(12, 0);

    Some(vec![w0, w1, w2, w3])
}

/// A block plaintext looks like text: printable ASCII, the CR/LF a `.txt` file
/// may contain, or the `0x01` the encrypter pads its read buffer with.
fn is_text(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|&b| (0x20..0x7f).contains(&b) || b == 1 || b == 10 || b == 13)
}

/// Walk the nonce chain back to round 0 and return the first plaintext that
/// looks like text.
///
/// Every branch decrypts the block, so only the plaintext distinguishes them;
/// wrong branches produce random bytes. `round` is the round `candidates` are
/// the nonces of.
fn search(state: &[Vec<u8>], candidates: &[[u16; 6]], round: usize) -> Option<Vec<u8>> {
    for candidate in candidates {
        let Some(previous) = invert_round(state, &bytes_le(candidate)) else {
            continue;
        };

        if round == 0 {
            let plaintext = previous.concat();
            if is_text(&plaintext) {
                return Some(plaintext);
            }
            continue;
        }

        // `N_{round+1} = A(N_round)`, so the previous round's nonce is the
        // `A`-preimage of this one.
        if let Some(plaintext) = search(&previous, &invert_rkey(candidate, Rkey::A), round - 1) {
            return Some(plaintext);
        }
    }

    None
}

/// Recover one 48-byte plaintext block from its 60-byte ciphertext alone.
///
/// The trailing word is `B(N_11)`; inverting it yields the last round's nonce
/// and every earlier one is an `A`-preimage of the next.
fn decrypt_block(ct: &[u8]) -> Option<Vec<u8>> {
    let state: Vec<Vec<u8>> = ct[..48].chunks(12).map(<[u8]>::to_vec).collect();
    let candidates = invert_rkey(&words_le(&ct[48..60]), Rkey::B);
    search(&state, &candidates, ROUNDS - 1)
}

/// `solve --decrypt <file> [-o <output>]`: recover every block's random nonce
/// from the block itself and write the plaintext (default: `flag-rust.txt`).
pub fn run() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut input: Option<String> = None;
    let mut output: Option<String> = None;
    let mut index = 1;

    while index < args.len() {
        match args[index].as_str() {
            "--decrypt" => {}
            "-o" | "--output" => {
                index += 1;
                let Some(path) = args.get(index) else {
                    eprintln!("usage: {} --decrypt <file> [-o <output>]", args[0]);
                    return Ok(());
                };
                output = Some(path.clone());
            }
            path => input = Some(path.to_string()),
        }
        index += 1;
    }

    let Some(input) = input else {
        eprintln!("usage: {} --decrypt <file> [-o <output>]", args[0]);
        return Ok(());
    };

    let ciphertext = std::fs::read(&input)?;
    if ciphertext.is_empty() || ciphertext.len() % 60 != 0 {
        eprintln!("decrypt: not a whole number of 60-byte blocks");
        return Ok(());
    }

    let blocks: Vec<&[u8]> = ciphertext.chunks(60).collect();
    let workers = std::thread::available_parallelism()
        .map_or(1, |count| count.get())
        .min(blocks.len());

    // Blocks are independent, so they decrypt in parallel; each worker returns
    // the blocks it handled and the results are stitched back in order.
    let mut per_block: Vec<Option<Vec<u8>>> = vec![None; blocks.len()];
    let finished: Vec<Vec<(usize, Option<Vec<u8>>)>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|worker| {
                let blocks = &blocks;
                scope.spawn(move || {
                    let mut out = Vec::new();
                    let mut index = worker;
                    while index < blocks.len() {
                        let plaintext = decrypt_block(blocks[index]);
                        if plaintext.is_none() {
                            eprintln!("  block {}: no key candidate", index + 1);
                        }
                        out.push((index, plaintext));
                        index += workers;
                    }
                    out
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("worker panicked"))
            .collect()
    });

    for (index, plaintext) in finished.into_iter().flatten() {
        per_block[index] = plaintext;
    }

    let Some(blocks) = per_block.into_iter().collect::<Option<Vec<Vec<u8>>>>() else {
        eprintln!("decrypt: no solution found (or a lossy round, M0 = 0 mod p)");
        return Ok(());
    };

    // The encrypter fills its 48-byte read buffer with 0x01 before every read,
    // so trailing 0x01 is padding rather than content.
    let bytes = blocks.concat();
    let end = bytes.iter().rposition(|&b| b != 1).map_or(0, |i| i + 1);
    let output = output.unwrap_or_else(|| "flag-rust.txt".to_string());
    std::fs::write(&output, &bytes[..end])?;
    println!("Decryption completed :) ({} bytes) -> {}", end, output);

    Ok(())
}
