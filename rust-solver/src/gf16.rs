//! GF(2^16) arithmetic plus the small polynomial machinery needed to invert the
//! round-key derivation algebraically.
//!
//! The round-key maps are quadratic systems in six words. Rather than guessing
//! two words and searching 2^32 candidates, each system is reduced here to a
//! pair of univariate polynomials in one word: guessing that one word leaves the
//! rest determined as rational functions, and the two unused equations become
//! polynomials whose common roots are the solutions.

use std::sync::LazyLock;

use crate::encrypt::gf16_mul;

/// Log/antilog tables under `x^16 + x^5 + x^3 + x + 1`.
///
/// `2` has multiplicative order 21845, so the tables are built from a generator
/// found by trial.
struct Gf {
    log: Box<[u16; 0x10000]>,
    exp: Box<[u16; 0x20000]>,
}

static GF: LazyLock<Gf> = LazyLock::new(|| {
    let generator = (2u32..=0xffff)
        .find(|&candidate| {
            let mut x = 1u16;
            let mut order = 0u32;
            loop {
                x = gf16_mul(x, candidate as u16);
                order += 1;
                if x == 1 {
                    break;
                }
            }
            order == 0xffff
        })
        .expect("the reduction polynomial is not primitive");

    let mut log = Box::new([0u16; 0x10000]);
    let mut exp = Box::new([0u16; 0x20000]);
    let mut x = 1u16;
    for i in 0..0xffffusize {
        exp[i] = x;
        log[x as usize] = i as u16;
        x = gf16_mul(x, generator as u16);
    }
    for i in 0xffff..0x20000usize {
        exp[i] = exp[i - 0xffff];
    }

    Gf { log, exp }
});

pub fn mul(a: u16, b: u16) -> u16 {
    if a == 0 || b == 0 {
        return 0;
    }
    GF.exp[GF.log[a as usize] as usize + GF.log[b as usize] as usize]
}

/// `a^-1`; returns 1 for 0, so callers must screen zeros out.
pub fn inv(a: u16) -> u16 {
    GF.exp[0xffff - GF.log[a as usize] as usize]
}

pub fn div(a: u16, b: u16) -> u16 {
    assert!(b != 0, "division by zero in GF(2^16)");
    mul(a, inv(b))
}

/// Polynomials over GF(2^16), coefficients low to high, no trailing zeros.
pub type Poly = Vec<u16>;

pub fn trim(p: &mut Poly) {
    while p.len() > 1 && *p.last().unwrap() == 0 {
        p.pop();
    }
}

pub fn add(a: &[u16], b: &[u16]) -> Poly {
    let mut out = vec![0u16; a.len().max(b.len())];
    for (i, out) in out.iter_mut().enumerate() {
        *out = a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
    }
    trim(&mut out);
    out
}

pub fn pmul(a: &[u16], b: &[u16]) -> Poly {
    let mut out = vec![0u16; a.len() + b.len() - 1];
    for (i, &x) in a.iter().enumerate() {
        if x == 0 {
            continue;
        }
        for (j, &y) in b.iter().enumerate() {
            out[i + j] ^= mul(x, y);
        }
    }
    trim(&mut out);
    out
}

pub fn pmod(a: &[u16], m: &[u16]) -> Poly {
    pdivmod(a, m).1
}

/// Returns `(quotient, remainder)`.
pub fn pdivmod(a: &[u16], b: &[u16]) -> (Poly, Poly) {
    let mut rem = a.to_vec();
    trim(&mut rem);

    let mut divisor = b.to_vec();
    trim(&mut divisor);
    let lead = *divisor.last().expect("empty divisor");

    if divisor.len() == 1 {
        assert!(lead != 0, "division by the zero polynomial");
        let scale = inv(lead);
        return (rem.iter().map(|&c| mul(c, scale)).collect(), vec![0]);
    }

    if rem.len() < divisor.len() {
        return (vec![0], rem);
    }

    let lead_inv = inv(lead);
    let mut quotient = vec![0u16; rem.len() - divisor.len() + 1];

    while rem.len() >= divisor.len() {
        let shift = rem.len() - divisor.len();
        let factor = mul(*rem.last().unwrap(), lead_inv);
        quotient[shift] ^= factor;
        for (i, &c) in divisor.iter().enumerate() {
            rem[i + shift] ^= mul(factor, c);
        }
        trim(&mut rem);
        if rem.len() == 1 && rem[0] == 0 {
            break;
        }
    }

    trim(&mut quotient);
    (quotient, rem)
}

pub fn pgcd(a: &[u16], b: &[u16]) -> Poly {
    let mut x = a.to_vec();
    let mut y = b.to_vec();
    trim(&mut x);
    trim(&mut y);
    while !(y.len() == 1 && y[0] == 0) {
        let r = pmod(&x, &y);
        x = y;
        y = r;
    }
    // Normalise to a monic representative.
    let lead = *x.last().unwrap();
    if lead != 1 && lead != 0 {
        let scale = inv(lead);
        for c in x.iter_mut() {
            *c = mul(*c, scale);
        }
    }
    x
}

pub fn pmulmod(a: &[u16], b: &[u16], m: &[u16]) -> Poly {
    pmod(&pmul(a, b), m)
}

/// `base^exp mod m` by square and multiply.
pub fn ppowmod(base: &[u16], exp: u32, m: &[u16]) -> Poly {
    let mut result: Poly = vec![1];
    let mut square = pmod(base, m);
    let mut remaining = exp;
    while remaining != 0 {
        if remaining & 1 == 1 {
            result = pmulmod(&result, &square, m);
        }
        square = pmulmod(&square, &square, m);
        remaining >>= 1;
    }
    result
}

/// Every root in GF(2^16) of `f`, without multiplicity.
///
/// `gcd(f, x^(2^16) + x)` keeps exactly the distinct linear factors; those are
/// then split apart with the characteristic-2 Cantor-Zassenhaus trace map.
pub fn roots(f: &[u16]) -> Vec<u16> {
    let mut f = f.to_vec();
    trim(&mut f);
    if f.len() <= 1 {
        return Vec::new();
    }

    let x = vec![0u16, 1];
    let mut xq = ppowmod(&x, 1 << 16, &f);
    if xq.len() < 2 {
        xq.resize(2, 0);
    }
    xq[1] ^= 1;
    trim(&mut xq);

    let split_product = pgcd(&f, &xq);
    let mut found = Vec::new();
    split_linear(&split_product, &mut found);
    found.sort_unstable();
    found.dedup();
    found
}

fn split_linear(g: &[u16], out: &mut Vec<u16>) {
    if g.len() <= 1 {
        return;
    }
    if g.len() == 2 {
        out.push(div(g[0], g[1]));
        return;
    }

    // Trace map of beta*x: T(z) = z + z^2 + ... + z^(2^15).
    let mut seed = 0x9e37u32;
    loop {
        seed = seed.wrapping_mul(0x85eb_ca6b).wrapping_add(1);
        let beta = (seed >> 8) as u16;
        if beta == 0 {
            continue;
        }

        let mut term = pmulmod(&[0, beta], &[1], g);
        let mut trace = term.clone();
        for _ in 1..16 {
            term = pmulmod(&term, &term, g);
            trace = add(&trace, &term);
        }

        let d = pgcd(g, &trace);
        if d.len() > 1 && d.len() < g.len() {
            let cofactor = pdivmod(g, &d).0;
            split_linear(&d, out);
            split_linear(&cofactor, out);
            return;
        }
    }
}

/// A rational function over GF(2^16) in a single variable, kept as a fraction so
/// that intermediate propagations can divide without introducing roots.
#[derive(Clone)]
pub struct Rat {
    num: Poly,
    den: Poly,
}

impl Rat {
    pub fn constant(c: u16) -> Self {
        Self { num: vec![c], den: vec![1] }
    }

    pub fn variable() -> Self {
        Self { num: vec![0, 1], den: vec![1] }
    }

    fn reduced(num: Poly, den: Poly) -> Self {
        let mut num = num;
        let mut den = den;
        trim(&mut num);
        trim(&mut den);
        if !(den.len() == 1 && den[0] == 0) {
            let g = pgcd(&num, &den);
            if g.len() > 1 {
                num = pdivmod(&num, &g).0;
                den = pdivmod(&den, &g).0;
            }
        }
        Self { num, den }
    }

    pub fn add(&self, other: &Self) -> Self {
        let num = add(&pmul(&self.num, &other.den), &pmul(&other.num, &self.den));
        let den = pmul(&self.den, &other.den);
        Self::reduced(num, den)
    }

    pub fn mul(&self, other: &Self) -> Self {
        Self::reduced(pmul(&self.num, &other.num), pmul(&self.den, &other.den))
    }

    pub fn div(&self, other: &Self) -> Self {
        Self::reduced(pmul(&self.num, &other.den), pmul(&self.den, &other.num))
    }

    pub fn numerator(&self) -> Poly {
        self.num.clone()
    }

    pub fn denominator(&self) -> Poly {
        self.den.clone()
    }

    /// True when the rational function is identically zero, which for a
    /// propagation intermediate means the guessed word was outside the
    /// parametrisation's domain.
    pub fn is_zero(&self) -> bool {
        self.num.len() == 1 && self.num[0] == 0
    }
}

/// True when the polynomial is the zero polynomial.
pub fn is_zero(p: &[u16]) -> bool {
    p.len() == 1 && p[0] == 0
}

/// `base^exp` in GF(2^16).
pub fn fpow(base: u16, exp: u32) -> u16 {
    let mut result = 1u16;
    let mut square = base;
    let mut remaining = exp;
    while remaining != 0 {
        if remaining & 1 == 1 {
            result = mul(result, square);
        }
        square = mul(square, square);
        remaining >>= 1;
    }
    result
}

/// Resultant of two univariate polynomials over GF(2^16).
///
/// Uses `res(a,b) = lc(b)^(deg a - deg r) * res(b, r)` with `r = a mod b`; the
/// usual `(-1)^(deg a * deg b)` sign is trivial in characteristic two, so it is
/// omitted.
pub fn resultant(a: &[u16], b: &[u16]) -> u16 {
    let mut a = a.to_vec();
    let mut b = b.to_vec();
    trim(&mut a);
    trim(&mut b);
    resultant_trimmed(&a, &b)
}

fn resultant_trimmed(a: &[u16], b: &[u16]) -> u16 {
    let m = a.len() - 1;
    let n = b.len() - 1;
    if m == 0 {
        return fpow(a[0], n as u32);
    }
    if n == 0 {
        return fpow(b[0], m as u32);
    }

    let (_, mut r) = pdivmod(a, b);
    trim(&mut r);
    if is_zero(&r) {
        return 0;
    }

    let dr = r.len() - 1;
    mul(fpow(b[n], (m - dr) as u32), resultant_trimmed(b, &r))
}

/// Divide `f` by `x + a`, assuming `a` is a root of `f` (synthetic division).
fn div_linear(f: &[u16], a: u16) -> Poly {
    let n = f.len();
    let mut quotient = vec![0u16; n - 1];
    let mut carry = 0u16;
    for k in (0..n - 1).rev() {
        let coefficient = f[k + 1] ^ mul(a, carry);
        quotient[k] = coefficient;
        carry = coefficient;
    }
    quotient
}

/// Lagrange interpolation over GF(2^16) through `(xs, ys)`, which must have the
/// same length and distinct `xs`. Returns the unique polynomial of degree below
/// `xs.len()` that passes through them.
pub fn interpolate(xs: &[u16], ys: &[u16]) -> Poly {
    assert_eq!(xs.len(), ys.len(), "interpolation needs as many values as points");
    assert!(!xs.is_empty(), "interpolation needs at least one point");

    let mut locator: Poly = vec![1];
    for &x in xs {
        locator = pmul(&locator, &[x, 1]);
    }

    let mut result: Poly = vec![0];
    for i in 0..xs.len() {
        let mut basis = div_linear(&locator, xs[i]);
        let denominator = eval(&basis, xs[i]);
        let scale = div(ys[i], denominator);
        for coefficient in basis.iter_mut() {
            *coefficient = mul(*coefficient, scale);
        }
        result = add(&result, &basis);
    }
    trim(&mut result);
    result
}

/// Evaluate a polynomial at a point.
pub fn eval(p: &[u16], x: u16) -> u16 {
    let mut acc = 0u16;
    for &c in p.iter().rev() {
        acc = mul(acc, x) ^ c;
    }
    acc
}

/// Evaluate `num/den` at a point, or `None` where the denominator vanishes.
pub fn eval_rat(num: &[u16], den: &[u16], x: u16) -> Option<u16> {
    let d = eval(den, x);
    if d == 0 {
        return None;
    }
    Some(div(eval(num, x), d))
}
