# OutPost Held-Out & Smoke Test Binary Manifest

This manifest documents all stock binaries, held-out evaluation samples, and synthetic test binaries used to evaluate the OutPost static analysis engine (Stage 1 PE and ELF deep parsers, hashing, indicators, and verdict logic).

In accordance with repository hygiene and safety policies:
- **No binary files are committed to git.** All samples reside in temporary evaluation directories (`/tmp/heldout_eval/`, `/tmp/throwaway_eval/`) or are built from source probes (`tests/probes/`).
- Only this markdown manifest is tracked under version control.
- All real-world files are benign vendor executables, stock OS distribution packages, or synthetic compile-time test fixtures. Zero live malware is executed.

---

## Evaluation Binary Catalog

| Binary Name | Format | SHA-256 | Size (Bytes) | Provenance & Retrieval Command | Expected Verdict | Current Verdict | Risk Score | Key Assessment Factors / Notes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `ls` | ELF 64-bit LSB (x86-64) | `29abfee0d588cfbee70103be11aa0a2f81b0d8c1292341e2345fc9f3ffa1558b` | 166,640 | Stock Ubuntu Jammy host binary (`/bin/ls`) | `clean` | `no_indicators_found_limited` | 0 | Stock benign coreutil; dynamic linking against `libc.so.6` & `libcap.so.2` scores 0. |
| `notepad.exe` | PE32+ (x86-64) | `8e6472bce3c981d560c1ffdbad82b455371932bf381b06036b331ada5227e060` | 284,346 | Wine MinGW PE build (`/usr/lib/wine/x86_64-windows/notepad.exe`) | `clean` | `no_indicators_found_limited` | 0 | Trailing MinGW COFF symbol & string tables (2,700 + 3,118 bytes) recognized as debug info, not an overlay. |
| `probe_elf` | ELF 64-bit LSB (x86-64) | `13fa7a774b13d4eb118eb8f0555676603e8deae1e130123dc23f842dd53825f6` | 16,912 | Compiled from `tests/probes/c_probe/main.c` via `gcc -O2` | `clean` | `no_indicators_found_limited` | 0 | Ground-truth network/process probe; dynamic networking symbols & RFC 5737 TEST-NET IPs score 0. |
| `7z2408-x64.exe` | PE32 (x86) | `67cb9d3452c9dd974b04f4a5fd842dbcba8184f2344ff72e3662d7cdb68b099b` | 1,624,144 | `curl -sSL -o 7z2408-x64.exe "https://www.7-zip.org/a/7z2408-x64.exe"` | `inconclusive` | `insufficient_evidence` | 0 | 7-Zip SFX installer stub with 1.58 MB compressed overlay payload. Informational observation; `could_not_analyze: ["compressed overlay payload not inspected"]`. |
| `7z.dll` | PE32+ (x86-64) | `e79ddfb6319dbf9bac6382035d23597dad979db5e71a605d81a61ee817c1e812` | 1,892,864 | Extracted from `7z2408-x64.exe` via `7z e -y 7z2408-x64.exe 7z.dll` | `clean` | `no_indicators_found_limited` | 0 | Vendor engine DLL. Valid PE32+ structure with no anomalous sections or unverified elevations. |
| `nano_ubuntu_jammy` | ELF 64-bit LSB (x86-64) | `c436995a1790379cc502650638551cb52ded4ca7be6c599596064b0c04da5fce` | 283,144 | Extracted from `nano_6.2-1_amd64.deb` (`http://archive.ubuntu.com/ubuntu/pool/main/n/nano/nano_6.2-1_amd64.deb`) | `clean` | `no_indicators_found_limited` | 0 | Standard Ubuntu CLI text editor; clean dynamic imports and standard PT_LOAD segments. |
| `sigcheck64.exe` | PE32+ (x86-64) | `f3d671b4bab4714746d0034104363d4f6deef591e979e8e37170803e8960487d` | 528,184 | `curl -sSL -o sigcheck64.exe "https://live.sysinternals.com/sigcheck64.exe"` | `clean` | `no_indicators_found_limited` | 0 | Signed Microsoft Sysinternals tool. Authenticode certificate reported under `signature_info` with `status: "signature present (unverified)"` and zero risk-reduction weight. |
| `strings64.exe` | PE32+ (x86-64) | `05dbb43499bcff44424c7ac2d987ea9e9742cd90afe360e84ba0bccade17f71b` | 478,088 | `curl -sSL -o strings64.exe "https://live.sysinternals.com/strings64.exe"` | `clean` | `no_indicators_found_limited` | 0 | Signed Microsoft Sysinternals tool. CRT TLS callbacks and registry inspection APIs remain informational capabilities without structural anomalies. |
| `kernel32.dll` | PE32+ (x86-64) | `f3bf0d1e2931c91911ceb15ae509aac1d63a7a50d02362871f1d6dc3f2b27769` | 446,138 | Copied from `/usr/lib/wine/x86_64-windows/kernel32.dll` | `clean` | `no_indicators_found_limited` | 0 | Wine core OS subsystem DLL. Exporting memory allocation/process APIs does not elevate threat score without caller injection context. |
| `cmd.exe` | PE32+ (x86-64) | `56c4c6030cdf15e3534ad5e031d551095848d493b3ae1023c348aa642da03436` | 1,031,826 | Copied from `/usr/lib/wine/x86_64-windows/cmd.exe` | `clean` | `no_indicators_found_limited` | 0 | Wine CLI command interpreter; normal execution APIs remain informational capabilities. |
| `System.Runtime.dll` | PE32 (x86) | `6cdde6cd382e449d956614da955b515003ddb5feb831cf5e4dbcc8eac017b550` | 34,816 | Copied from `/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.x/System.Runtime.dll` | `inconclusive` | `insufficient_evidence` | 0 | .NET Managed assembly (`IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`); `could_not_analyze: ["managed assembly; native analysis limited"]`. |
| `busybox_static` | ELF 64-bit LSB (x86-64) | `6e123e7f3202a8c1e9b1f94d8941580a25135382b99e8d3e34fb858bba311348` | 1,131,168 | `curl -sSL -o busybox "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox"` | `clean` | `no_indicators_found_limited` | 0 | Statically linked musl binary; lack of dynamic section is handled without false packer indicators. |
| `ls_ubuntu_jammy` | ELF 64-bit LSB (x86-64) | `8696974df4fc39af88ee23e307139afc533064f976da82172de823c3ad66f444` | 138,208 | Extracted from `coreutils_8.32-4.1ubuntu1_amd64.deb` | `clean` | `no_indicators_found_limited` | 0 | Upstream Ubuntu 22.04 LTS coreutils release binary; unstripped symbols and standard sections. |
| `ls_upx_packed` | ELF 64-bit LSB (x86-64) | `d9738bc5fa243b6d4a2af7ffafa96165714f63daac5029a49fa38412cd420430` | 56,784 | Packed via `upx -o ls_upx_packed ls_ubuntu_jammy` (UPX 4.2.4) | `inconclusive` | `insufficient_evidence` | 25 | UPX packer detected via `UPX!` magic at offset `0xEC`; `could_not_analyze: ["packed_executable_code", "obfuscated_imports"]`. Single consolidated packer factor. |
| `notepad_upx.exe` | PE32+ (x86-64) | `303c7dc54be427242bb252bacc10e97397e3f49e32038384539bb801bde28f6c` | 110,778 | Packed via `upx -o notepad_upx.exe notepad.exe` (UPX 4.2.4) | `inconclusive` | `insufficient_evidence` | 25 | UPX packer detected via `UPX!` magic at offset `0x205` and sections `UPX0 (RWX), UPX1 (RWX)`. Single consolidated factor. |
| `injection_rwx.exe` | PE32+ (x86-64) | `11e7e08e7eaf5e422d622e80c42651849a8d34c6a3299eb3dad5d5472d615b71` | 2,048 | Generated via `gen_synthetic_pe.py (is_rwx=True)` | `suspicious` | `suspicious` | 45 | Injection imports (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`) corroborated by anomalous writable+executable `.evil` section (`0xE0000040`). |
| `injection_clean_rx.exe` | PE32+ (x86-64) | `efa06bab9e91a8cb1867e47c6f446b13ff69869b14e685e07144a69d428cd1d2` | 2,048 | Generated via `gen_synthetic_pe.py (is_rwx=False)` | `clean` | `no_indicators_found_limited` | 0 | Identical injection imports in standard non-writable `.text` RX section (`0x60000020`); correctly evaluated as informational capability with score 0. |

---

## Instructions for Independent Reproduction

To reproduce this evaluation from scratch:

```bash
# 1. Prepare evaluation directory
mkdir -p /tmp/throwaway_eval /tmp/heldout_eval

# 2. Download vendor packages
curl -sSL -o /tmp/throwaway_eval/7z2408-x64.exe "https://www.7-zip.org/a/7z2408-x64.exe"
curl -sSL -o /tmp/throwaway_eval/sigcheck64.exe "https://live.sysinternals.com/sigcheck64.exe"
curl -sSL -o /tmp/heldout_eval/strings64.exe "https://live.sysinternals.com/strings64.exe"
curl -sSL -o /tmp/heldout_eval/busybox_static "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox"
chmod +x /tmp/heldout_eval/busybox_static

# 3. Extract 7z.dll and nano
7z e -y -o/tmp/throwaway_eval /tmp/throwaway_eval/7z2408-x64.exe 7z.dll
curl -sSL -o /tmp/throwaway_eval/nano.deb "http://archive.ubuntu.com/ubuntu/pool/main/n/nano/nano_6.2-1_amd64.deb"
ar x /tmp/throwaway_eval/nano.deb data.tar.xz --output /tmp/throwaway_eval/
tar -xf /tmp/throwaway_eval/data.tar.xz -C /tmp/throwaway_eval/ ./bin/nano
mv /tmp/throwaway_eval/bin/nano /tmp/throwaway_eval/nano_ubuntu_jammy

# 4. Copy host Wine and .NET binaries
cp /usr/lib/wine/x86_64-windows/notepad.exe /tmp/heldout_eval/notepad.exe
cp /usr/lib/wine/x86_64-windows/kernel32.dll /tmp/heldout_eval/kernel32.dll
cp /usr/lib/wine/x86_64-windows/cmd.exe /tmp/heldout_eval/cmd.exe
cp /usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.*/System.Runtime.dll /tmp/heldout_eval/System.Runtime.dll

# 5. Build UPX samples (requires upx >= 4.2.0)
upx -o /tmp/heldout_eval/notepad_upx.exe /tmp/heldout_eval/notepad.exe
upx -o /tmp/heldout_eval/ls_upx_packed /bin/ls
```
