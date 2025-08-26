# Scheme Index

| Name          | Description                               | Source | Note          |
|---------------|-------------------------------------------|--------|---------------|
| `a_0_oe.json` | Construction 4.5 (optimized encryption)   | [1]    | = Constr. 4.5 |
| `a_0_ok.json` | Construction 4.5 (optimized keygen)       | [1]    | = Constr. 4.5 |
| `a_1_xx.json` | `a_0_??.json` + no FDH                    | [1]    |               |
| `a_2_xx.json` | `a_0_??.json` + other groups              | [1]    |               |
| `a_3_xx.json` | `a_0_??.json` + hashed non-lone vars      | [1]    |               |
| `a_4_xx.json` | `a_0_??.json` + hashed common vars        | [1]    |               |
| `a_5_xx.json` | `a_0_??.json` + no deduplications         | [1]    |               |
| `a_6_xx.json` | `a_0_??.json` + single auth only          | [1]    |               |
| `a_7_xx.json` | `a_0_??.json` + scaling factor            | [1]    |               |
| `b_0_oe.json` | Definition 16 (optimized encryption)      | [2]    | = Constr. 4.6 |
| `b_0_ok.json` | Definition 16 (optimized keygen)          | [2]    | = Constr. 4.6 |
| `b_1_xx.json` | `b_0_??.json` + no FDH                    | [2]    |               |
| `b_2_xx.json` | `b_0_??.json` + other groups              | [2]    |               |
| `b_3_xx.json` | `b_0_??.json` + hashed non-lone vars      | [2]    |               |
| `b_4_xx.json` | `b_0_??.json` + hashed common vars        | [2]    |               |
| `b_5_xx.json` | `b_0_??.json` + no deduplications         | [2]    |               |
| `b_6_xx.json` | `b_0_??.json` + single auth only          | [2]    |               |
| `b_7_xx.json` | `b_0_??.json` + scaling factor            | [2]    |               |
| `c_0_oe.json` | Wat11-I (optimized encryption)            | [3]    | = Constr. 4.1 |
| `c_0_ok.json` | Wat11-I (optimized keygen)                | [3]    | = Constr. 4.1 |
| `c_1_oe.json` | Wat11-IV (optimized encryption)           | [3]    | = Constr. 4.7 |
| `c_1_ok.json` | Wat11-Iv (optimized keygen)               | [3]    | = Constr. 4.7 |
| `c_2_xx.json` | `c_0_??.json` + other groups              | [3]    |               |
| `c_3_xx.json` | `c_0_??.json` + hashed non-lone vars      | [3]    |               |
| `c_4_xx.json` | `c_0_??.json` + hashed common vars        | [3]    |               |
| `c_5_xx.json` | _not applicabale_                         | [3]    |               |
| `c_6_xx.json` | _not applicabale_                         | [3]    |               |
| `c_7_xx.json` | `c_0_??.json` + scaling factor            | [3]    |               |
| `d_0_oe.json` | RW13 (optimized encryption)               | [4]    | = Constr. 4.2 |
| `d_0_ok.json` | RW13 (optimized keygen)                   | [4]    | = Constr. 4.2 |
| `d_1_xx.json` | `d_0_??.json` + other groups              | [4]    |               |
| `d_2_xx.json` | `d_0_??.json` + hashed non-lone vars      | [4]    |               |
| `d_3_xx.json` | `d_0_??.json` + hashed common vars        | [4]    |               |
| `d_4_xx.json` | `d_0_??.json` + mixed hash                | [4]    |               |
| `d_5_xx.json` | _not applicabale_                         | [4]    |               |
| `d_6_xx.json` | _not applicabale_                         | [4]    |               |
| `d_7_xx.json` | `d_0_??.json` + scaling factor            | [4]    |               |
| `e_0_od.json` | AC17 (optimized decryption)               | [5]    | = Constr. 4.3 |
| `e_0_oe.json` | AC17 (optimized encryption)               | [5]    | = Constr. 4.3 |
| `e_0_ok.json` | AC17 (optimized keygen)                   | [5]    | = Constr. 4.3 |
| `e_1_oe.json` | AC17-LU (optimized encryption)            | [5]    | = Constr. 4.8 |
| `e_1_ok.json` | AC17-LU (optimized keygen)                | [5]    | = Constr. 4.8 |
| `e_2_xx.json` | `e_0_??.json` + other groups              | [5]    |               |
| `e_3_xx.json` | `e_0_??.json` + hashed non-lone vars      | [5]    |               |
| `e_4_xx.json` | `e_0_??.json` + hashed common vars        | [5]    |               |
| `e_5_xx.json` | `e_0_??.json` + no deduplications         | [5]    |               |
| `e_6_xx.json` | _not applicabale_                         | [5]    |               |
| `e_7_xx.json` | `e_0_??.json` + scaling factor            | [5]    |               |

# References

[1]: [Attaining Basically Everything in Attribute-Based Encryption](https://repository.ubn.ru.nl/bitstream/handle/2066/295550/295550.pdf?sequence=1&isAllowed=y)

[2]: [A Practical Compiler for Attribute-Based Encryption](https://eprint.iacr.org/2023/143.pdf)

[3]: [Ciphertext-Policy Attribute-Based Encryption](https://eprint.iacr.org/2008/290.pdf)

[4]: [Practical Construction and New Proof Methods for Large Universe ABE](https://dl.acm.org/doi/10.1145/2508859.2516672)

[5]: [Simplifying Design and Analysis of Complex Predicate Encryption Schemes](https://eprint.iacr.org/2017/233)
