# Benchmarking with profile-guided optimisation

Profile-guided optimisation can be used to *potentially* improve benchmarking reliability and eliminate code-alignment-related noise, albeit this hypothesis is currently unproven. This works by compiling the `waf_benchmark `binary with instrumentation, running the benchmark and using the generated profile to recompile the binary. 

Two scripts have been provided, one with PGO and LTO support and another one with PGO, LTO and BOLT, although this latter one hasn't been tweaked in order to provide better performance than simply using PGO + LTO, it also requires two profile-generation stages so the entire process requires more than double the time a typical benchmark would. 

Building with LTO and PGO can be done from the root directory, with the following command:

```sh
./benchmark/scripts/build_with_pgo.sh
```

This will perform the first stage build, generate the profile and rebuild the optimised `waf_benchmark` binary in the `build/benchmark/` directory.

In a similar manner, building with LTO, PGO and BOLT can be done from the root directory with the following command:

```sh
./benchmark/scripts/build_with_pgo_and_bolt.sh
```

This will also perform all relevant stages, with the final optimised binary contained in `build/benchmark/`.

