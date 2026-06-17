# Algorithm parameter interface

This interface returns objective parameters for the 9 authentication algorithms.
It does not include recommendation, score, security level, NIST/LWC status, advantage text, limitation text, or any subjective evaluation.

## C interface

```c
int auth_get_algorithm_security_info(struct auth_algorithm_security_info *out_infos, int max_count);
const char* auth_get_algorithm_security_json();
```

## Fields

```json
{
  "alg_id": 13,
  "name": "TinyJAMBU-256",
  "family": "TinyJAMBU",
  "key_bits": 256,
  "nonce_bits": 96,
  "tag_bits": 64
}
```

## Algorithm groups

- TinyJAMBU: 128 / 192 / 256-bit keys
- SCHWAEMM: 128 / 192 / 256-bit keys
- LEA-CCM: 128 / 192 / 256-bit keys

When attack mode triggers re-authentication, the fixed target is `CMD_FORCE_ALGS:13,23,33`.
