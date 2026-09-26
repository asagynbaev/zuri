# zuri

Payroll in stablecoins where salaries stay private, but the employee can still
prove their income to a landlord or a bank.

Salaries are paid with Token-2022 confidential transfers, so amounts are
encrypted on-chain. To prove "I earned at least X every month", the employee
adds up the encrypted transfers of each month and produces zero-knowledge
proofs: that a fresh Pedersen commitment matches each month's encrypted total,
and that every commitment minus X is non-negative. The verifier rebuilds the
encrypted totals from chain data by itself and checks the proofs. It never
learns the amounts.

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
cargo run -- setup                # test stablecoin + confidential accounts
cargo run -- pay 3200@2026-04     # confidential salary for April
cargo run -- apply                # employee applies pending balance
cargo run -- balances
cargo run -- inspect              # read every salary back from the chain
cargo run -- prove 3000 --monthly # writes .zuri/proof.json
```

The pay period is a memo signed by the employer in the same transaction as the
transfer. Salaries without one count for the month they were paid in. Without
`--monthly` the proof covers the total of all salaries. Up to 8 months fit into
one proof.

`demo` runs setup, pays three salaries, applies and prints balances.

Verifying a proof only needs the file, the employer address and the amount you
want to check:

```
$ cargo run --bin zuri-verify -- .zuri/proof.json \
    --employer 8T4QErDUXhwfY3fRi4EW7PEtzHVT2nLiVqmXUVtXaoho --min 3000 --months 6
YES  7RcTotvETzwADrNpYHWhTso1EPCxeSJENMGW5poV9Xmb earned at least 3000.00 in each of 6 months, 2026-04 to 2026-09
     from 8T4QErDUXhwfY3fRi4EW7PEtzHVT2nLiVqmXUVtXaoho, 9 transfers
     paid between 2026-09-23 and 2026-09-25
     tx set 55d6f7900a8d7517a0335f97e7a1dabdb93907ab23ed4a7dd2f6e841fcfc1ce8
```

The verifier rejects transfers from another sender or to another recipient,
repeated signatures, transfers listed under the wrong month, a changed transfer
set, gaps between months and thresholds above the proven one.

## Web demo

```
cargo run --release --bin zuri-web     # or ./scripts/web.ps1
```

http://localhost:8787 is the employee side: salaries decrypted by month and a
form that turns "at least X every month for N months" into a proof and a link.
The link opens the verifier side, which checks the proof against Solana and
shows the months with the amounts blacked out.

The employee page uses the employee key from `.zuri/`, standing in for a
wallet. The verifier page only needs the proof and chain data.

The public devnet RPC allows about ten `getTransaction` calls per window, so
the first load takes around half a minute. Point `ZURI_RPC_URL` at a dedicated
devnet endpoint to avoid that.

## Where the ciphertexts are

A confidential transfer with proofs in context accounts takes five
transactions. The `Transfer` instruction itself only has the auditor's
ciphertexts. The ones for the recipient are in the data of the
`VerifyBatchedGroupedCiphertext3HandlesValidity` instruction that wrote the
validity context account, which the transfer references. `src/onchain.rs` has
the byte layout and finds that instruction starting from the transfer
signature. Proofs carry the signature of each validity transaction as well,
so the verifier doesn't have to search account history for it.

## Not done yet

- employer verification, so "from a verified employer" means something
- verifying the proof on-chain
- generating proofs in the browser or wallet instead of the demo server
