# Frontend display guide

Group algorithms by `family` and show only objective parameters:

- `alg_id`
- `name`
- `family`
- `key_bits`
- `nonce_bits`
- `tag_bits`

Do not display score, recommendation, security level, or subjective descriptions.

Forced re-authentication target under attack mode is:

```text
13,23,33
```

That means the 256-bit key variant from each family:

- TinyJAMBU-256
- SCHWAEMM256-256
- LEA-CCM-256
