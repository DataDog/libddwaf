#!/bin/bash

echo "Compiling Stage 1"
mkdir build-stage1 ; cd build-stage1
echo $(pwd)
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DLIBDDWAF_BENCHMARK_PGO_STAGE1=ON
make -j $(nproc) waf_benchmark 
cd ..

echo "Generating profile"
./build-stage1/benchmark/waf_benchmark --scenarios=$(pwd)/benchmark/scenarios/ --iterations=1000 --output=none --fixtures="random"
llvm-profdata-19 merge -output profile.profdata *.profraw
rm -rf build-stage1

echo "Compiling Stage 2"
mkdir build ; cd build
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DLIBDDWAF_BENCHMARK_PGO_PROFILE=$(pwd)/../profile.profdata
make -j $(nproc) waf_benchmark 
cd ..
