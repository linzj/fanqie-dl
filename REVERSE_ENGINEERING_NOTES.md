# libmetasec_ml.so Reverse Engineering Notes

## Binary: libmetasec_ml_fixed.so (from com.dragon.read v7.1.3.32)

## Confirmed Crypto Primitives

| Algorithm | Function Address | Size | Identification Method |
|-----------|-----------------|------|----------------------|
| **MD5** | `sub_24307C` | 2656B | Standard T-constants (-680876936=0xD76AA478, etc.), rotation amounts 7/12/17/22/5/9/14/20 |
| **SHA-256** | `sub_245354` | ~500B | Standard sigma functions (ROR 2/13/22, ROR 6/11/25), 64 rounds with K constants from `qword_95B80` |
| **AES-128 key expansion** | `sub_241E9C` | 1104B | Handles key sizes 16/24/32, S-box tables at `qword_916B8`/`qword_91AF8`/`qword_91ED0` |
| **AES block encrypt** | `sub_243F10` | 4508B | Standard AES round structure with S-box lookups |

### Wrapper Functions
- `sub_243C34` = MD5 full hash (init + update + finalize)
- `sub_245630` = SHA-256 full hash
- `sub_258A48` = SHA-256 wrapper (called from signing code)
- `sub_2585F4` = MD5 wrapper
- `sub_259C1C` / `sub_25AA48` = AES cipher setup (mode dispatch)
- `sub_259DBC` = AES-CBC mode operation (2996B)

## NOT Found (Exhaustive Search)

- **SM3**: No IV constants (0x7380166F), no T constants (0x79CC4519, 0x7A879D8A), no P0/P1 permutations
- **Simon-128/256**: No Z constant (0x3DC94C3A046D678B), no 72-round loop with ROL 1/2/8
- **Community sign key**: 0xAC1ADAAE... not found in any byte order or XOR encoding

## Obfuscation Techniques

1. **Control Flow Flattening (CFF)**: Main signing functions use switch-based dispatch with computed state variables
2. **XOR String Encryption**: All strings decrypted at runtime via `sub_167E54(encrypted, output, key)` where `output[i] = encrypted[i] ^ key[i]`
3. **Constant Encryption**: Crypto constants not stored as immediates; computed or decrypted at runtime
4. **Anti-Analysis**: Self-referencing address computations in `sub_283748`

## Signing Architecture

### Entry Point
```
Java: ms.bd.c.r4.onCallToAddSecurityFactor(String url, Map headers)
  -> MSManager.frameSign(String, int)
    -> JNI (dynamically registered in JNI_OnLoad at 0x27B41C)
      -> sub_29CCD4 (signing orchestrator)
        -> sub_29CF58 (CFF-obfuscated core, references PAYLOAD_MD5, X-BD-KMSV)
```

### Key Strings Found
- `ML_DoHttpReqSignIT` (0x38bbaa)
- `PAYLOAD_MD5` (0x11f995)
- `X-BD-KMSV` (0x11f98b)
- `X-SS-STUB` (0x38de54)
- `X-METASEC-MODE` (0x38bbbd)
- `X-BD-CLIENT-KEY` (0x38bbce)
- `METASEC` (0x6f476) - used in logging

### Algorithm Differences: Fanqie vs TikTok Community

| Component | TikTok Community | Fanqie Novel (this SO) |
|-----------|-----------------|----------------------|
| Body/Query Hash | SM3 | **SHA-256** |
| Key Derivation | SM3(key+salt+key) | **SHA-256(key+salt+key)** |
| Inner Encryption | Simon-128/256 (72 rounds) | **AES-128-ECB** |
| Outer Encryption | AES-128-CBC | AES-128-CBC (same) |
| X-Gorgon | MD5 + S-box | MD5 + S-box (same) |
| X-Ladon | Speck-128/128 | Speck-128/128 (likely same) |

## Code Changes Made

### `src/signer/argus.rs`
- Replaced `sm3::sm3_hash()` with `sha2::Sha256::digest()` for body/query hashing
- Replaced `simon::simon_enc()` with `aes::Aes128::encrypt_block()` (ECB mode, block-by-block)
- Key derivation: `SHA256(SIGN_KEY + b'\xf2\x81\x61\x6f' + SIGN_KEY)` → first 16 bytes as AES-128 key

## Remaining Unknowns

1. **SIGN_KEY**: The 32-byte signing key may be different for Fanqie vs TikTok. Currently using community key.
2. **Protobuf fields**: Magic value (0x20200929), SDK version string, and other fields may differ.
3. **X-Helios / X-Medusa**: Not yet implemented. These headers may also be required.
4. **Key rotation**: The server may have updated keys since this binary version.

## Recommended Next Steps

1. Test with real API requests to see if SHA-256+AES variant is accepted
2. If rejected, use Frida on ARM64 to capture actual sign key and field values
3. Implement X-Helios and X-Medusa if needed
