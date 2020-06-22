# Instructions for running fuzzer

Each fuzz target can be run with:

```
$ cargo fuzz run XX
```

Where `XX` is replaced with one fuzz target in `targets/`.

For speed improvements consider adding the flags `-s leaks -O`. To set Zsaniter=leaks and release mode optimisations.

## Additional instructions

Some fuzz targets require generation of parameters these can be generated from
[here](https://github.com/filecoin-project/rust-fil-proofs/blob/master/filecoin-proofs/src/bin/paramcache.rs)
by running:

```
$ cargo run --bin paramcache --release
```

This will take a very long time, so I will also recommend commenting out some `PUBLISHED_SECTOR_SIZES`.
Comment out all the sector sizes except `SECTOR_SIZE_2_KIB`.
