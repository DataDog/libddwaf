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
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DLIBDDWAF_BENCHMARK_PGO_STAGE2_PROFILE=$(pwd)/../profile.profdata -DLIBDDWAF_ENABLE_LTO=ON
make -j $(nproc) waf_benchmark 

