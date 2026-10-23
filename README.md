# Google CTF 2024 — Rusty School

Write-up e solução do desafio **Rusty School** (Reversing / Crypto, 406 pontos,
6 solves) do Google CTF 2024.

O repositório contém o binário, o ciphertext, dois solvers independentes
(SageMath e Rust) e a documentação do desafio.

## Estrutura

```text
.
├── attachments/
│   ├── rustyschool              # binário ELF x86-64 (Rust 1.70.0)
│   └── flag.txt.encrypted       # 7.980 bytes = 133 blocos de 60 bytes
├── sage-solver/
│   ├── solve.py                 # solver SageMath
│   └── README.md
├── rust-solver/
│   ├── Cargo.toml
│   ├── Cargo.lock
│   ├── src/                     # inclui encrypt.rs (cifrador reconstruído via Ghidra)
│   └── README.md                # solver Rust + detalhes da implementação
├── docs/
│   ├── SETUP.md                 # instalação do SageMath 10.x e Rust
│   └── presentation.pdf
├── WRITEUP.md                   # write-up completo
├── flag-sage.txt                # gerado pelo solver SageMath
├── flag-rust.txt                # gerado pelo solver Rust
├── LICENSE
└── README.md
```

## Solvers

| Solver | Entrada | Saída | Tempo aproximado |
|---|---|---|---|
| SageMath | `attachments/flag.txt.encrypted` | `flag-sage.txt` | minutos |
| Rust | `attachments/flag.txt.encrypted` | `flag-rust.txt` | ~1–2 s |

Ambos produzem 6.359 bytes com md5
`468a48469137692c853e3c665dc49a23`. Para conferir:

```bash
cmp flag-sage.txt flag-rust.txt
```

### SageMath

Requer SageMath **10.x** (`from_integer()`/`to_integer()`); versões 9.x não
funcionam. Ative o ambiente SageMath da sua instalação e rode a partir da raiz
do repositório:

```bash
python sage-solver/solve.py attachments/flag.txt.encrypted
```

Confira a versão com `sage --version`.

Opções:

```bash
python sage-solver/solve.py <input> -o <output> -j <workers>
```

O solver falha com código de saída diferente de zero se qualquer bloco não
decifrar.

### Rust

```bash
cargo run --release --manifest-path rust-solver/Cargo.toml -- \
  --decrypt attachments/flag.txt.encrypted
# -> flag-rust.txt
```

Use `-o/--output` para escolher outro caminho:

```bash
cargo run --release --manifest-path rust-solver/Cargo.toml -- \
  --decrypt attachments/flag.txt.encrypted -o /tmp/flag.txt
```

## Documentação

* [`WRITEUP.md`](WRITEUP.md) — análise completa da cifra e da solução.
* [`docs/SETUP.md`](docs/SETUP.md) — instalação do SageMath 10.x e Rust.
* [`docs/presentation.pdf`](docs/presentation.pdf) — apresentação da versão
  inicial; alguns caminhos de arquivo citados nela podem estar desatualizados.
* [`sage-solver/README.md`](sage-solver/README.md) e
  [`rust-solver/README.md`](rust-solver/README.md) — detalhes de cada solver.

## Como a cifra funciona

* Rede Feistel de **4 ramos**, 12 rodadas, ramos de 12 bytes.
* Entrada em blocos de **48 bytes**; saída de **60 bytes** = 48 bytes de estado
  + 12 bytes de estado de chave por bloco.
* Rodada: MD5 e SHA-1 truncados em 12 bytes, XOR, e aritmética modular módulo
  o primo de 96 bits:

  ```text
  P = 79160129948973046149879599747
  ```

* Escalonamento de chaves (`derive`) sobre **GF(2¹⁶)**, polinômio redutor
  `x¹⁶ + x⁵ + x³ + x + 1` (`0x2B`).
* A inversão resolve sistemas quadráticos de 6 equações em GF(2¹⁶), retrocede
  as 12 rodadas e trata as raízes múltiplas.
* O bloco final tem 23 bytes úteis e padding `0x01`; os dois solvers truncam
  no primeiro `0x01`, produzindo os 6.359 bytes exatos.

## Observação

O histórico completo da limpeza e das versões antigas permanece no Git.
