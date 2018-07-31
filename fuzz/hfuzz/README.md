# Fuzzing using Honggfuzz

First, install the cargo-hfuzz command line tool:

```
cargo install honggfuzz
```

While in this directory, execute:

```
cargo hfuzz run hfuzz
```

When a crash was found:

```
cargo hfuzz run-debug hfuzz fuzzing_workspace/*.fuzz
```

This will reproduce the crash in lldb.
