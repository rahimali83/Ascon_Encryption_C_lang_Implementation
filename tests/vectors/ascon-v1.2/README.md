# Official Ascon v1.2 public KATs

Place the KAT text files here, using these expected filenames:
- aead128.txt
- aead128a.txt
- aead80pq.txt
- hash256.txt
- xof.txt
- xofa.txt

Format: classic LWC/NIST-style records with key-value lines and blank-line separators.
Fields (case-insensitive; examples):
- AEAD: Key, Nonce (or Npub), AD (or AAD), PT (or Msg), CT (or Ciphertext), Tag (or MAC)
- Hash: Msg (or PT), Digest (or MD)
- XOF: Msg (or PT), Output (or Out), OutLen (optional)

Source: https://github.com/ascon/ascon-c (tag v1.2). If you use another canonical source, ensure the fields match.

Tests will automatically skip if files are absent. To run:
  cmake --build <build-dir> --target test_kat_aead test_kat_hash_kat test_kat_xof_kat && ctest -R ascon_kat -V
