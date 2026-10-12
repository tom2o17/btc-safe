// Prints policy ids computed by LedgerHQ's own client (npm ledger-bitcoin), so the Rust
// re-implementation in crates/core/src/ledger.rs can be checked against it.
import { WalletPolicy } from "ledger-bitcoin";
const keys = [
  "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
  "[f5acc2fd/48'/1'/0'/2']key-two",
  "[0badc0de/48'/1'/0'/2']key-three",
];
console.log(new WalletPolicy("Cold storage", "wsh(sortedmulti(2,@0/**,@1/**))", keys.slice(0, 2)).getId().toString("hex"));
console.log(new WalletPolicy("Treasury", "wsh(sortedmulti(2,@0/**,@1/**,@2/**))", keys).getId().toString("hex"));
