Get the latest YARA rules (to be run periodically with a cron job, maybe once a day)
```bash
bash getLatestYARArules.sh
```

Run the server in dev
```bash
cargo run
```

Build the final package
```bash
cargo build --release -p gA-V
# Final binary: ./target/release/gA-V
```

Note: Uses around 1 Go of RAM

## API Doc

### Reload latest rules and hashes

YARA: ``POST /recompile``
Hashes: ``POST /reload_hash``

May take ~10-15 seconds on good hardware.

### Run a scan

``PUT /scan`` with the file to test in the body/payload

Response:

Malware detected with hashes:
```js
{
  result: "malware",
  detection: "hash",
  hash: <hash_hex>,
}
```

Malware detected with YARA rules:
```js
{
  result: "malware",
  detection: "YARA",
  rules: [
    <yara_rule_name1>,
    <yara_rule_name2>,
    ...
  ],
}
```

"Safe" file:
```js
{
  result: "safe"
}
```
