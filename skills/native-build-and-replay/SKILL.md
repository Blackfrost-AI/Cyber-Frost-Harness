---
name: native-build-and-replay
description: Reuse or repair native sanitizer builds and fuzz targets while avoiding architecture-mixed objects, unnecessary full builds, and toolchain drift.
---

# Native build and replay

Prefer the shipped executable in `/out`. It was built with the matching project toolchain and sanitizer. Rebuild only when a concrete experiment requires instrumentation, a source change, or a missing target.

## Before rebuilding

- Run `file` on the target and a sample of object files and static libraries.
- Read `/src/build.sh`, project build metadata, and `/out/*.options`.
- Record `$CC`, `$CXX`, `$CFLAGS`, `$CXXFLAGS`, `$LIB_FUZZING_ENGINE`, `$SRC`, `$OUT`, and `$WORK`.
- Remove or isolate stale objects when architecture or compiler provenance differs.
- Build in a new directory instead of layering over shipped objects.

Mixed `EM_X86_64` and `AArch64` objects, incompatible C++ standard libraries, and stale generated configuration files are hard failures. Detect them before linking:

```bash
find BUILD -type f \( -name '*.o' -o -name '*.a' \) -print0 |
  xargs -0 -r file | sort -u
```

## Focused build

Use the project's own fuzz build script when possible. Preserve the OSS-Fuzz environment variables and request only the required target. For manual builds:

- compile libraries with `-fsanitize=fuzzer-no-link,address` or the image's supplied flags;
- link the final harness with `$LIB_FUZZING_ENGINE` or `-fsanitize=fuzzer,address`;
- keep debug symbols and frame pointers;
- disable optional components rather than repairing the entire application suite;
- verify the resulting binary on one known-good seed immediately.

Do not poll long builds with repeated sleeps. Launch once with a status file and inspect process state, status, and the first actionable errors in one command. Stop a build that cannot contribute to the current hypothesis.
