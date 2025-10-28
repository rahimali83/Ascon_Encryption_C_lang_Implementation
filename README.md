# Ascon_Hash256

A minimal C implementation and demo of the Ascon-Hash256 function (256-bit hash), organized as a small, self-contained project. Ascon is the NIST Lightweight Cryptography winner for authenticated encryption and hashing. This project focuses on hashing only.

Note: This implementation is for educational and experimental purposes. Do not use in production without thorough review, testing against official test vectors, and hardening.

## Features

- Ascon-Hash256 (32-byte digest) in C
- Simple API for hashing byte buffers
- Small codebase with a demo program
- CMake-based build

## Project Structure

- CMakeLists.txt — CMake configuration
- main.c — Hashing implementation and demo (CLI output)

## Build

Prerequisites:
- A C compiler (e.g., gcc/clang/MSVC)
- CMake (3.15+ recommended)

Build (out-of-source):

```shell script
# From the project root
cmake -S . -B build
cmake --build build --config Release
```


This produces an executable in the build output directory (platform/toolchain dependent), for example:
- build/Ascon-Hash256 (Unix-like)
- build/Release/Ascon-Hash256.exe (Windows/MSVC with multi-config)

## Run

The demo executable prints the 32-byte hash (in hex) of:
- The empty string ""
- The ASCII string "abc"

```shell script
# From the project root
./build/Ascon-Hash256
```


Example output (digest values will be shown by the program):
- Hashing empty string ""
- Hashing string "abc"

## Using the hashing API in your code

The project offers a single-call API to compute a 256-bit digest.

```c++
// C
#include <stdint.h>
#include <stddef.h>

// Computes Ascon-Hash256 digest.
// - msg: pointer to input bytes
// - msg_len: input size in bytes
// - digest: pointer to a 32-byte buffer to receive the hash
void ascon_hash256(const uint8_t* msg, size_t msg_len, uint8_t* digest);
```


Minimal usage example:

```c++
// C
#include <stdio.h>
#include <stdint.h>
#include <string.h>

int main(void) {
    const char* text = "hello world";
    uint8_t digest[32];

    ascon_hash256((const uint8_t*)text, strlen(text), digest);

    for (int i = 0; i < 32; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");
    return 0;
}
```


Notes:
- The API operates on raw bytes; pass any binary buffer with its size.
- The output digest is 32 bytes (256 bits).

## Testing and verification

- Compare digests against reference implementations or official test vectors to validate correctness.
- Consider adding unit tests that cover:
  - Empty input
  - Short messages (e.g., “a”, “abc”)
  - Messages spanning multiple rate blocks
  - Randomized inputs
  - Known-answer tests (KATs)

## Performance and build tips

- Compile with optimizations for better performance:
  - GCC/Clang: `-O3 -march=native` when appropriate
  - MSVC: `/O2`
- Ensure constant-time behavior is preserved if you adapt code paths.

## Security considerations

- This repository is a minimal, educational implementation and has not undergone formal cryptographic review.
- Timing side channels, portability pitfalls, and undefined behavior should be carefully audited before any security-sensitive use.
- Validate endianness assumptions and alignment on your target platforms.

## License

Refer to the source file headers for licensing and usage terms. If unsure, contact the project owner before redistribution or commercial use.

## Streaming APIs (Hash and XOF)

The library provides streaming (incremental) APIs in addition to one-shot functions.

- Hash-256 streaming (see `include/ascon/ascon_hash.h`):
```
ascon_hash256_ctx ctx; uint8_t dig[32];
ascon_hash256_init(&ctx);
// absorb in chunks
ascon_hash256_update(&ctx, part1, len1);
ascon_hash256_update(&ctx, part2, len2);
// finalize (applies 10* padding once) and squeeze 32 bytes
ascon_hash256_final(&ctx, dig);
```

- XOF/XOFa streaming (see `include/ascon/ascon_xof.h`):
```
ascon_xof_ctx xc; uint8_t out[64];
ascon_xof_init(&xc);           // or ascon_xofa_init(&xc)
ascon_xof_absorb(&xc, msg, mlen);
ascon_xof_finalize(&xc);
ascon_xof_squeeze(&xc, out, 64);  // can be called multiple times
```

CLI includes simple demos:
```
# Streaming Hash-256 (chunk size optional, default 8)
./cmake-build-debug/Ascon_Hash256 hash256-stream --text "hello" --chunksize 3

# Streaming XOF/XOFa with multi-call squeeze
./cmake-build-debug/Ascon_Hash256 xof-stream  --text "abc" --outlen 40 --chunksize 5
./cmake-build-debug/Ascon_Hash256 xofa-stream --text "abc" --outlen 40 --chunksize 5
```

## Tests (non‑KAT)

Non‑KAT tests can be run individually or via CTest label:
```
# Build specific targets
cmake --build cmake-build-debug --target test_hash test_hash_variants test_xof test_aead128 test_aead128a test_aead80pq

# Run via CTest label
ctest --test-dir cmake-build-debug -L non_kat -VV
```

Note on KATs: Official KAT alignment is currently deferred; Hash/Hasha/XOF use placeholder IVs. Once official constants/vectors are provided, enable KAT tests under `tests/vectors/ascon-v1.2/` and re-baseline.

## References

- Ascon project page: https://ascon.iaik.tugraz.at/
- NIST Lightweight Cryptography (LWC) project: https://csrc.nist.gov/Projects/lightweight-cryptography

## Contributing

Issues and improvement suggestions are welcome. For substantive changes, please include:
- A clear description of the motivation
- Tests (including known-answer tests where applicable)
- Platform/CI notes if relevant

## Contact

For questions or feedback, please open an issue or reach out to the project maintainers.
