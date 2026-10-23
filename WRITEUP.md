# WriteUp: Google CTF 2024 — Rusty School

**Categoria:** Reverse Engineering / Cryptography<br>
**Pontuação:** 406 pontos (6 solves)<br>
**Autores da Solução:** `perfect blue` (superfashi, Riatre, cts)<br>
**Binário:** ELF 64-bit x86-64 (compilado com `rustc 1.70.0`)

---

## 1. Resumo Executivo & Visão Geral

O desafio **Rusty School** do Google CTF 2024 apresenta um executável binário escrito em Rust que realiza a cifragem de arquivos. O programa divide a entrada em blocos independentes de 48 bytes e gera saídas de 60 bytes (adicionando 12 bytes de estado aleatório para garantir a reversibilidade do processo).

A estrutura criptográfica consiste em uma **Rede Feistel de 4 ramos** executada ao longo de 12 rodadas por bloco. A derivação de chaves (*key schedule*) opera em um corpo finito GF(2¹⁶) estendido pelo polinômio redutor `x¹⁶ + x⁵ + x³ + x + 1` (`0x2B`). A inversão do mecanismo requer a resolução de um sistema de equações quadráticas em SageMath via variedades algébricas, além do tratamento do *backtracking* para gerenciar múltiplas raízes candidatas.

---

## 2. Engenharia Reversa em Rust: Desafios e Análise Dinâmica

Analisar binários Rust em descompiladores convencionais (como IDA Pro ou Hex-Rays) é notoriamente complexo. O açúcar sintático do Rust (como o operador `?`), o tratamento de exceções, os gerenciadores de alocação de memória e as otimizações agressivas do LLVM geram dezenas de linhas de código de suporte (*boilerplate*) para operações simples.

Frente a essa verbosidade, a abordagem mais eficaz foi a **análise dinâmica combinada com patching**:

1. **Identificação da chamada de sistema `getrandom`**: Verificou-se que o executável gera 12 bytes aleatórios por bloco via `getrandom`.
2. **Patching para Determinismo**: No editor hexadecimal, alterou-se a variável indicadora de disponibilidade do `getrandom` para `0` e redirecionou-se o caminho `/dev/urandom` para `./my_urandom`. Criando um link simbólico `ln -s /dev/zero ./my_urandom`, o comportamento do gerador tornou-se 100% reproduzível no GDB.
3. **Redução das Rodadas**: Para facilitar a depuração no GDB, alterou-se temporariamente o contador de rodadas de 12 para 1 rodada.

Além da instrumentação dinâmica, o cifrador foi reconstruído em Rust a partir do descompilado do Ghidra (`rust-solver/src/encrypt.rs`). Com nonce fixo, essa reconstrução reproduz a saída do binário byte a byte e serve como oráculo para validar a inversão das rodadas e o solver Rust. O módulo não participa do caminho de decifração.

---

## 3. Arquitetura da Cifra Feistel de 4 Ramos

A cifra opera sobre 4 ramos de 12 bytes cada ($b_0, b_1, b_2, b_3$), totalizando 48 bytes de texto plano. Em cada uma das 12 rodadas:

1. **Derivação das Chaves de Rodada**: A partir de um *seed* de 12 bytes $rv_0$, derivam-se $rv_0' = \text{derive}(rv_0, m=0)$ e $rv_1 = \text{derive}(rv_0, m=1)$.
2. **Mistura das Funções Hash**:
   $\text{cb}_1 = b_0 \oplus \text{MD5}(rv_0 \mathbin{\Vert} b_2)[:12]$<br>
   $\text{cb}_2 = b_1 \oplus \text{SHA1}(rv_1 \mathbin{\Vert} \text{bs})[:12]$
3. **Transformação Modular no Primo $P$**:
   Convertendo os ramos para inteiros *little-endian*, calcula-se:
   $\text{bs} = \left((i_1 + i_3) \cdot i_0 + i_2^{i_1}\right) \pmod P$<br>
   Onde $P = 79160129948973046149879599747$ é um número primo de 96 bits (12 bytes).
4. **Permutação dos Ramos**: Os ramos são rotacionados para a próxima rodada como $(b_2, \text{cb}_1, \text{bs}, \text{cb}_2)$.

---

## 4. Função de Derivação de Chaves e Modelagem em GF(2¹⁶)

A função `derive` recebe 12 bytes (interpretados como um vetor $a = (a_0, a_1, a_2, a_3, a_4, a_5)$ de 6 elementos em GF(2¹⁶)) e retorna 12 bytes, conforme o valor de $m$:

Para $m = 0$:

$$
\text{derive}(a) = (a_0 a_1 + a_4,\ a_1 a_2 + a_5,\ a_2 a_3 + a_0,\ a_3 a_4 + a_1,\ a_4 a_5 + a_2,\ a_5 a_0 + a_3)
$$

Para $m = 1$:

$$
\text{derive}(a) = (a_2 a_3 + a_5,\ a_3 a_4 + a_0,\ a_4 a_5 + a_1,\ a_5 a_0 + a_2,\ a_0 a_1 + a_3,\ a_1 a_2 + a_4)
$$

Para inverter a função `derive`, constrói-se um **sistema de 6 equações polinomialmente quadráticas em 6 variáveis** sobre o corpo finito GF(2¹⁶) com o polinômio redutor `x¹⁶ + x⁵ + x³ + x + 1` (`0x2B`).

---

## 5. Implementação do Solver no SageMath e Correções de API

A inversão algébrica utiliza **Ideais de Anéis de Polinômios e Variedades Algébricas** em SageMath (`Ideal.variety()`).

### Migração de API (SageMath 10+)
O script original utilizava o método legado `.fetch_int()`, descontinuado nas versões modernas do SageMath (10.x). A solução foi atualizar as chamadas para os métodos oficiais `.from_integer()` e `.to_integer()`.

### Inversão Estrita do 4º Ramo Feistel
Para evitar erros de conversão (`OverflowError`), a inversão do ramo de mistura modular deve manter o resultado estritamente no intervalo $[0, P-1]$:

$$
b_3 = \left(\left(\left(\text{bs} - b_2^{b_1}\right) \cdot b_0^{-1} \pmod P\right) - b_1\right) \pmod P
$$

Em seguida, `b_3.to_bytes(12, 'little')` produz os 12 bytes do ramo.

---

## 6. Algoritmo de Busca e Multiprocessamento

Como o sistema quadrático em GF(2¹⁶) pode admitir mais de uma raiz válida por rodada, o algoritmo realiza uma **busca em largura (BFS)** revertendo as 12 rodadas de trás para frente. Em cada rodada, todos os estados candidatos são expandidos e as duplicatas são eliminadas. Para rodadas intermediárias, utilizam-se as equações combinadas de $m=0$ e $m=1$ (`solve2`), restringindo o conjunto de soluções candidatas.

Devido à independência dos 133 blocos de 60 bytes do arquivo cifrado (`flag.txt.encrypted`), a decifração foi otimizada processando os blocos em paralelo com `ProcessPoolExecutor` e o contexto `spawn`. O tempo total depende do hardware e do número de workers (`-j`).

---

## 7. Implementação

O solver SageMath completo está em [`sage-solver/solve.py`](sage-solver/solve.py). O fluxo principal é:

1. `solve_(..., m)` e `solve2_(...)` invertem o *key schedule* via `Ideal.variety()`.
2. `do_one_round` inverte uma rodada Feistel, incluindo o ramo modular.
3. `decrypt_block` faz a busca em largura pelas 12 rodadas e valida o texto plano.
4. `main` processa os blocos com `ProcessPoolExecutor` no contexto `spawn`.

### Solver Rust

O solver Rust em [`rust-solver/`](rust-solver/) é independente do SageMath:

- `decrypt.rs` inverte o *key schedule* por parametrização e resultantes, sem `Ideal.variety()`, e faz DFS sobre a cadeia de nonces com filtro de texto plano.
- `encrypt.rs` é uma reconstrução do cifrador original feita com Ghidra, usada como oráculo de testes.
- `gf16.rs` implementa GF(2¹⁶) com tabelas de log/antilog e polinômios univariados.

Os dois solvers produzem os mesmos 6.359 bytes (md5 `468a48469137692c853e3c665dc49a23`). O Rust é ordens de magnitude mais rápido por evitar a resolução genérica de variedades a cada rodada.

---

## 8. Conclusão e Resultados

A combinação da análise de engenharia reversa dinâmica com a modelagem em corpo finito GF(2¹⁶) permitiu reverter completamente a cifra do desafio **Rusty School**. Os dois solvers independentes, em SageMath e Rust, reproduzem os mesmos 6.359 bytes, sem falhas de execução.
