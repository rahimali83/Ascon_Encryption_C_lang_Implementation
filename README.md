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
