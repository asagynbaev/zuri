# zuri

Payroll in stablecoins where salaries stay private, but the employee can still
prove their income to a landlord or a bank.

Salaries are paid with Token-2022 confidential transfers, so amounts are
encrypted on-chain. To prove "I earned at least X", the employee adds up the
encrypted transfers they received and produces two zero-knowledge proofs: that
a fresh Pedersen commitment matches the encrypted total, and that the
commitment minus X is non-negative. The verifier rebuilds the encrypted total
from chain data by itself and checks both proofs. It never learns the amounts.

Devnet only for now.

## Build

```
cargo build
```

Needs a recent stable Rust (1.97.1+). On Windows without the MSVC build tools
there is `scripts/cargo.ps1`, which runs cargo in the official Docker image:

```
./scripts/cargo.ps1 run -- demo
```

## Usage

Keypairs and the local payroll log live in `.zuri/`. The employer wallet pays
all fees and needs about 1 SOL on devnet.

```
cargo run -- setup              # test stablecoin + confidential accounts
cargo run -- pay 3200 3450.50   # confidential salary transfers
cargo run -- apply              # employee applies pending balance
cargo run -- balances
cargo run -- inspect            # read every salary back from the chain
cargo run -- prove 9000         # writes .zuri/proof.json
```

`demo` runs setup, pays three salaries, applies and prints balances.

Verifying a proof only needs the file, the employer address and the amount you
want to check:

```
$ cargo run --bin zuri-verify -- .zuri/proof.json --employer 8T4QErDUXhwfY3fRi4EW7PEtzHVT2nLiVqmXUVtXaoho --min 9000
YES  7RcTotvETzwADrNpYHWhTso1EPCxeSJENMGW5poV9Xmb earned at least 9000.00
     from 8T4QErDUXhwfY3fRi4EW7PEtzHVT2nLiVqmXUVtXaoho, 3 transfers
     between 2026-09-23 and 2026-09-23
     tx set ba9a51f3e31f4be8c33764f4b09311123eb54fe66433797370c66c2854b9dff4
```

The verifier rejects transfers from another sender or to another recipient,
repeated signatures, a changed transfer set and thresholds above the proven one.

## Where the ciphertexts are

A confidential transfer with proofs in context accounts takes five
transactions. The `Transfer` instruction itself only has the auditor's
ciphertexts. The ones for the recipient are in the data of the
`VerifyBatchedGroupedCiphertext3HandlesValidity` instruction that wrote the
validity context account, which the transfer references. `src/onchain.rs` has
the byte layout and finds that instruction starting from the transfer
signature.

## Not done yet

- per-month thresholds (one commitment per month in a batched range proof)
- employer verification, so "from a verified employer" means something
- verifying the proof on-chain
- a UI
