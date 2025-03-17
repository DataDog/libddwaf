#!/bin/bash

printf "\n--------------------------\nCompiling Stage 1\n--------------------------\n"
mkdir build-stage1 ; cd build-stage1
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DLIBDDWAF_BENCHMARK_PGO_STAGE1=ON -DLIBDDWAF_ENABLE_LTO=ON
make -j $(nproc) waf_benchmark 
cd ..

printf "\n--------------------------\nGenerating PGO Profile\n--------------------------\n"
./build-stage1/benchmark/waf_benchmark --scenarios=$(pwd)/benchmark/scenarios/ --iterations=1000 --output=none --fixtures="random"
llvm-profdata-19 merge -output profile.profdata *.profraw
rm -rf build-stage1

printf "\n--------------------------\nCompiling Stage 2\n--------------------------\n"
mkdir build ; cd build
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DLIBDDWAF_BENCHMARK_PGO_PROFILE=$(pwd)/../profile.profdata -DLIBDDWAF_ENABLE_LTO=ON
make -j $(nproc) waf_benchmark 

printf "\n--------------------------\nBOLT Instrumenting Binary\n--------------------------\n"
llvm-bolt-19 ./benchmark/waf_benchmark -o ./benchmark/waf_benchmark.instrumented -instrument
cd ..

printf "\n--------------------------\nGenerating BOLT Profile\n--------------------------\n"
./build/benchmark/waf_benchmark.instrumented --scenarios=$(pwd)/benchmark/scenarios/ --iterations=1000 --output=none --fixtures="random"
merge-fdata-19 /tmp/*.fdata > merged.profdata

printf "\n--------------------------\nGenerating Optimized Binary\n--------------------------\n"
llvm-bolt-19 ./build/benchmark/waf_benchmark -o ./build/benchmark/waf_benchmark.bolt -data=merged.profdata -reorder-blocks=ext-tsp -reorder-functions=hfsort -split-functions -split-all-cold -split-eh -dyno-stats
mv ./build/benchmark/waf_benchmark.bolt ./build/benchmark/waf_benchmark
