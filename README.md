# DelphiLibOpenSSL
A Delphi unit that provides complete static bindings to OpenSSL. Instead of dynamically loading OpenSSL DLLs at runtime, this project compiles OpenSSL C source code into `.obj` files and statically links them into Delphi applications. 
This eliminates DLL deployment complexity and ensures version consistency.
## Core Features
- **Static linking** - zero DLL deployment; everything compiles into a single `.exe` or `.bpl`
- Most complete Pascal translation of OpenSSL API headers (**~16,000 lines**), **4,993 API functions** (**~99.2%** api coverage),
  support for all major OpenSSL subsystems ( SSL/TLS, X.509, EVP, BIO, ASN.1, PKCS, CMS etc). see `Supported API Surface` chapter
- **Win32 + Win64** - pre-built objects for both platforms, multiple compiler toolchains
- **Reproducible builds** - build scripts for OpenSSL 3.x / 4.x branches see `Building Object Files` chapter
- **DUnitX test suite** - 89 tests covering initialization, crypto, certificates, digests, and protocols

## Supported API Surface
| Module | Functions | Description |
|--------|-----------|-------------|
| ASN.1 (`ASN1_`, `d2i_`, `i2d_`) | 760 | ASN.1 types, DER encoding/decoding |
| EVP (`EVP_`) | 640 | High-level cryptographic operations |
| X.509 (`X509_`, `X509V3_`) | 556 | Certificate creation, verification, extensions |
| SSL/TLS (`SSL_`, `TLS_`, `DTLS_`) | 522 | Protocol handling, contexts, sessions |
| OSSL (`OSSL_`) | 513 | OpenSSL 3 provider API, parameters, decoders |
| Big Numbers (`BN_`) | 185 | Arbitrary-precision integer arithmetic |
| BIO (`BIO_`) | 170 | Abstracted I/O (memory, file, socket, SSL) |
| EC (`EC_`, `ECDSA_`) | 146 | Elliptic curve keys and signatures |
| PEM (`PEM_`) | 140 | PEM-format read/write for keys and certs |
| PKCS (`PKCS5_`, `PKCS7_`, `PKCS8_`, `PKCS12_`) | 136 | PKCS standards (key derivation, envelopes, keystores) |
| Timestamp (`TS_`) | 124 | RFC 3161 timestamping |
| CMS (`CMS_`) | 111 | Cryptographic Message Syntax (S/MIME) |
| CRYPTO (`CRYPTO_`) | 101 | Core crypto utilities, memory, locking |
| Legacy Ciphers (`AES_`, `DES_`, `BF_`, …) | 92 | Block cipher low-level API |
| OPENSSL (`OPENSSL_`) | 92 | Library initialization, version, utilities |
| DH / DSA (`DH_`, `DSA_`) | 91 | Diffie-Hellman and DSA key agreement/signatures |
| OCSP (`OCSP_`) | 85 | Online Certificate Status Protocol |
| RSA (`RSA_`) | 81 | RSA key operations |
| Certificate Transparency (`CT_`, `SCT_`) | 49 | SCT verification, CT policy |
| Other (`UI_`, `SRP_`, `ERR_`, `OBJ_`, `RAND_`, …) | 192 | UI prompts, SRP, errors, OIDs, random, HMAC, CONF |


## Quick Start

1. Add `libOpenSSL3` to the `uses` clause of your project
2. In `libOpenSSL3.pas`, verify the version define matches your needs (`OPENSSL_3X` or `OPENSSL_4X`)
3. Build for the desired platform (Win32 or Win64)

```pascal
uses libOpenSSL3;

begin
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS or
                   OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nil);
  // Ready to use SSL/TLS, EVP, X.509, etc.
end.
```

By default the unit links  **4.x** objects. To switch to 3.x, comment out `{$DEFINE OPENSSL_4X}` and uncomment `{$DEFINE OPENSSL_3X}` at the top of `libOpenSSL3.pas`.

## Compiler / Platform Matrix

| Configuration | Compiler | Platform | Object Format | Convention | Symbol Prefix |
|---------------|----------|----------|---------------|------------|---------------|
| **BORLAND_32** _(default Win32)_ | BCC32 classic | Win32 | OMF | `register` | _(none)_ |
| **BCC32C** | BCC32C (Clang) | Win32 | OMF | `cdecl` | `_` |
| **MSC_32** | MSVC x86 | Win32 | COFF | `cdecl` | `_` |
| **MSC_64** _(default Win64)_ | MSVC x64 | Win64 | COFF | single ABI | _(none)_ |
| **BORLAND_64** | BCC64 (Clang) | Win64 | ELF | single ABI | _(none)_ |

To switch compilers, edit `libOpenSSL3.pas` — comment/uncomment the `{$DEFINE C_COMPILER_*}` lines in the compiler detection block (lines 86–97). For example, to use BCC64 for Win64 instead of the default MSVC:

```pascal
{$IFDEF CPUX64}
   //{$DEFINE C_COMPILER_MSC_64}      // < comment out MSVC
   {$DEFINE C_COMPILER_BORLAND_64}    // < uncomment BCC64
{$ENDIF}
```

## Building Object Files
Since static linking of C code in Delphi imposes certain requirements on the source code (such as the use of case-insensitive identifier names, linking order, and dependencies on external code), and the OpenSSL source code does not fully meet these requirements, this project uses an approach based on dynamically modifying the source file tree. This task is performed by a set of scripts located in the helpers/ directory. I have tried to describe the changes made in detail directly within these scripts.
A huge thank you to [Rudy Velthuis](http://rvelthuis.de/articles/articles-convert.html) for his series of posts in which he described the potential challenges associated with directly using compiled C code.
You are no longer with us, but your contribution remains invaluable.

### Prerequisites

| Tool | Required for | Notes |
|------|-------------|-------|
| **RAD Studio 12+** | BCC32 / BCC32C / BCC64 builds | Provides `bcc32`, `bcc32c`, `bcc64` compilers |
| **Visual Studio 2019+** | MSVC Win32 / Win64 builds | C++ workload with `cl.exe` |
| **Perl** (Strawberry Perl) | OpenSSL `Configure` step | Required by all build scripts |
| **Python 3.x** | Helper/patch scripts | C89 patching, Makefile patching, symbol fixups |

## OpenSSL Branch Selection

The project supports two OpenSSL branches simultaneously:

| Branch | Source Path | Object Dir | Pascal Define |
|--------|------------|------------|---------------|
| **3.x** | `c_src/openssl-openssl-3.6.1/` | `obj3/` | `OPENSSL_3X` |
| **4.x** _(default)_ | `c_src/openssl-openssl-4.0.0/` | `obj4/` | `OPENSSL_4X` |

**In Pascal:** set `{$DEFINE OPENSSL_3X}` or `{$DEFINE OPENSSL_4X}` at the top of `libOpenSSL3.pas`.
Only one may be active at a time (a compile-time guard enforces this).

**In build scripts:** set the `OPENSSL_BRANCH` environment variable before running:

```batch
set OPENSSL_BRANCH=3
build_openssl3_msvc_win64.bat
```

If `OPENSSL_BRANCH` is not set, it defaults to **4**.

## Building Object Files

### Prerequisites

| Tool | Version | Required For | Notes |
|------|---------|-------------|-------|
| **RAD Studio** | 12 Athens+ | BCC32 / BCC32C / BCC64 builds | Provides `bcc32`, `bcc32c`, `bcc64`, Borland `make` |
| **Visual Studio** | 2019+ | MSVC Win32 / Win64 builds | "Desktop development with C++" workload (`cl.exe`, `nmake.exe`) |
| **Perl** | Strawberry Perl 5.x | OpenSSL `Configure` step | Required by **all** build scripts |
| **Python** | 3.8+ | Helper/patch scripts | C89 patching, Makefile patching, symbol fixups |
| **NASM** | 2.15+ _(optional)_ | Assembly-optimized builds | MSVC scripts accept `no-asm` to skip; Embarcadero scripts always use `no-asm` |

### Build Configuration — `build_config.bat`

All build scripts delegate environment setup to `build_config.bat`. Edit this file **once** to match your machine:

```batch
REM === Machine-specific paths (edit for your environment) ====================
set "PERL_DIR=C:\programdata\strawberry\perl\bin"
set "RAD_STUDIO=D:\Embarcadero RAD Studio\23.0"
set "VS_BUILD=D:\VisualStudio2019\VC\Auxiliary\Build"
```

`build_config.bat` reads `OPENSSL_BRANCH` (default `4`) and resolves the source path and output directory automatically:

| Variable | How it's set | Example (branch 4) |
|----------|-------------|---------------------|
| `OPENSSL_BRANCH` | Environment or default `4` | `4` |
| `OPENSSL_SRC` | Auto from branch | `c_src\openssl-openssl-4.0.0` |
| `OBJ_DIR` | Auto from branch | `obj4` |
| `RSVARS` | Per target | `...\rsvars.bat` or `...\vcvars64.bat` |
| `OBJ_OUT` | Per target | `obj4\win64\vc` |

**Supported targets:** `bcc32_classic`, `bcc32c`, `bcc64`, `msvc_win32`, `msvc_win64`

### Build Scripts

| Script | Compiler | Platform | OpenSSL Target | Arguments |
|--------|----------|----------|---------------|-----------|
| `build_openssl3_cbuilder_classic_win32.bat` | bcc32 (C89) | Win32 | BC-32-classic | _(none)_ |
| `build_openssl3_cbuilder_win32.bat` | bcc32c (Clang) | Win32 | BC-32 | _(none)_ |
| `build_openssl3_cbuilder_win64.bat` | bcc64 (Clang) | Win64 | BC-64 | _(none)_ |
| `build_openssl3_msvc_win32.bat` | cl.exe x86 | Win32 | VC-WIN32 | `[no-asm]` |
| `build_openssl3_msvc_win64.bat` | cl.exe x64 | Win64 | VC-WIN64A | `[no-asm]` |

Each script:
1. Calls `build_config.bat <target>` to set up paths and compiler environment
2. Checks prerequisites (`perl`, compiler, `make`/`nmake`)
3. Runs OpenSSL `Configure` for the target toolchain
4. Applies helper patches (C89, Makefile, static link, case collisions)
5. Compiles with the platform-native `make` tool
6. Renames outputs with `_win32` / `_win64` suffixes into `%OBJ_DIR%\<platform>\<compiler>\`

**Example — build OpenSSL 4.x objects for MSVC Win64:**

```batch
set OPENSSL_BRANCH=4
build_openssl3_msvc_win64.bat
```

**Example — build OpenSSL 3.x objects for BCC32 classic Win32:**

```batch
set OPENSSL_BRANCH=3
build_openssl3_cbuilder_classic_win32.bat
```

> **Note:** Embarcadero compiler scripts always build with `no-asm` because NASM output is incompatible with the Embarcadero linker.

## Helper Scripts

### Build Pipeline Helpers (`helpers/`)

| File | Used By | Purpose |
|------|---------|---------|
| `patch_static_link.py` | all 5 scripts | Patch OpenSSL C sources for Delphi-compatible static linking |
| `patch_c89.py` | bcc32 classic | Downgrade C11 → C89 syntax for the classic Borland compiler |
| `patch_makefile_borland.py` | bcc32, bcc32c, bcc64 | Adapt generated Makefile for Embarcadero `make` |
| `ensure_bcc32_classic_conf.py` | bcc32 classic | Add `BC-32-classic` target to OpenSSL `50-cppbuilder.conf` |
| `gen_case_collision_fixes.py` | bcc32, bcc32c, msvc32 | Verify / generate `#define` renames for case-colliding symbols |
| `openssl_fix_case_collisions.h` | bcc32c, bcc64, msvc32, msvc64 | C header force-included via `/FI` — renames case-colliding internals |
| `ossl3_ucrt_helper_win64.obj` | msvc64 | Pre-compiled UCRT shim stubs copied into Win64 output |
| `ossl3_ucrt_helper_win64.c` | _(reference)_ | C source for the UCRT shim (rebuild manually if needed) |

## Testing

```batch
cd tests
"D:\Embarcadero RAD Studio\23.0\bin\rsvars.bat"
dcc32 -B -$D+ -$L+ -GD -M -U".." OpenSSL3Tests.dpr
OpenSSL3Tests.exe -b
```

The test suite (`tests/TestOpenSSL3API.pas`) contains **89 DUnitX tests** organized by area:
initialization, version info, error handling, EVP digests, EVP ciphers, BIO memory operations,
PEM/X.509 certificate I/O, RSA/EC key generation, SSL context creation, and provider queries.

## License

OpenSSL is licensed under the [Apache License 2.0](https://www.openssl.org/source/license.html).
The Delphi bindings in this repository follow the same license.

## PostScriptum
I don't have enough time to fully maintain this project, so I've decided to make it publicly available; I hope others will find it useful.
