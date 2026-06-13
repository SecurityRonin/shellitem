# shellitem

Decode a Windows `ITEMIDLIST` (PIDL) blob into typed shell items and a
reconstructed path — the reusable primitive behind LNK `LinkTargetIDList`,
registry ShellBags, and Jump Lists. A **decoder primitive, not an analyzer**
(no findings; forensic interpretation lives in the consuming crates), in the
spirit of `xpress-huffman` / `lznt1`.

```rust
use shellitem::{parse_idlist, reconstruct_path};
# let pidl_bytes: &[u8] = &[0, 0];
let items = parse_idlist(pidl_bytes);
let path  = reconstruct_path(&items); // "C:\\Users\\beth\\Downloads\\evil.exe"
```

`FileEntry` items carry the short + long name, size, modified/created/accessed
times, and the NTFS MFT entry+sequence from the `0xbeef0004` extension block.
Class/extension constants come from `forensicnomicon::shellbags`; the spec is
libyal's *Windows Shell Item format*.

**Consumers:** `lnk-core` (LinkTargetIDList), `winreg-artifacts` (ShellBags),
Jump Lists. Panic-free on untrusted input, `forbid(unsafe_code)`, fuzzed.

---

[Privacy Policy](https://securityronin.github.io/shellitem/privacy/) · [Terms of Service](https://securityronin.github.io/shellitem/terms/) · © 2026 Security Ronin Ltd
