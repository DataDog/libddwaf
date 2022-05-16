# Validator

## Building, test & validate

From the root directory of the repository, create a build directory and run CMake:
```
mkdir build
cmake -DCMAKE_BUILD_TYPE=Debug ..
``````

Alternatively, the build can be configured with `asan` and `ubsan`:
```
mkdir build
cmake -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_CXX_FLAGS="-fsanitize=address,leak,undefined -DASAN_BUILD" \
      -DCMAKE_C_FLAGS="-fsanitize=address,leak,undefined -DASAN_BUILD" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,leak,undefined" \
      -DCMAKE_MODULE_LINKER_FLAGS="-fsanitize=address,leak,undefined" ..
```

Once CMake has finished, build the validator:

```
make waf_validator
```

### Testing the validator

In order to trust that the validator is going to produce the right results when verifying the WAF output, some "unit" tests have been provided.

These tests can be executed, from the build directory, with the following command:

```
make test_validator
```

Alternatively, the "unit" tests can also be executed from the validator directory as follows:

```
../build/validator/waf_validator unit/*.yaml
```

This also allows executing individual tests as required.

### Validating the WAF

Testing the WAF with the validator can be done, from the build directory, with the following command:

```
make validate
```

Alternatively, some or all of these tests can be executed from the validator directory as follows:

```
../build/validator/waf_validator test/*.yaml
```

## Understanding the output of the validator

## Writing WAF validation tests

## Writing validator unit tests
