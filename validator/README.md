# Validator

The validator provides a framework for performing black box testing on the WAF, focusing on the inputs and outputs rather than the internals of the WAF, and making use of the API in the same manner as a library user would. 

To accomplish this. test specifications written in YAML are provided. Each test specification defines the following:
- Number of runs.
- Inputs per run.
- Expected rule matches per run; this can be one rule or many, to account for the slight uncertainty when it comes to duplicate matches.
- Expected return code per run.
- Expected outcome of the test; this allows us to define tests for features which we know aren't working yet.

In addition, one ruleset file is provided in the validator directory, which will contain the relevant rules to each individual test.

The validator also provides a self-test feature, which essentially leverages a similar YAML format which, instead of providing the set of inputs required for the WAF, provides the exact output the WAF would've produced. This also leverages the expected outcome of the test to produce self-tests which are expected to fail or pass but might not if the validator isn't implemented correctly.

The main components of the validator are:
- Validator itself, which is built in the relevant cmake build directory (`build/validator/waf_validator`).
- The WAF tests, located in `validator/tests`.
- The Ruleset, located in `validator/ruleset.yaml`.
- The validator self-tests, located in `validator/self-tests`.

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

In order ensure that the validator is going to produce the right results when verifying the WAF output, some self-tests have also been provided.

These tests can be executed, from the build directory, with the following command:

```
make test_validator
```

Alternatively, the self-tests can also be executed from the validator directory as follows:

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

The validator provides a result per test according to the specification, which not only defines the expected outcome of each run, but also whether the test should pass or fail. This makes it easy to write tests for currently unimplemented features or known inconsistencies, as well as enabling the self-testing feature of the validator.

When a test has passed and it's expected to pass, the following output is produced:
```
tests/rule7_004.yaml => Passed
```
When a test has passed and it's expected to fail, the following output is produced:
```
tests/rule9_001.yaml => Expected to fail but passed
```
_Note that this is considered a failure and the command will produce a non-zero output._

When a test has failed and it wasn't expected to fail, the following output is produced:
```
tests/rule8_001.yaml => Failed: run_test(80): monitor != good
- rule:
    id: 7
    name: rule7-common-flow
    tags:
      type: flow7_8
      category: category
  rule_matches:
    - operator: match_regex
      operator_value: rule7
      parameters:
        - address: rule7-input
          key_path:
            []
          value: rule7
          highlight:
            - rule7
```
As can be seen on the example, the output contains the validator assertion which failed in the form of `function(line)` as well as the error. To aid with verification, the WAF output is also provided on error.

Finally, when a test has failed and it was expected to fail, the following output is produced:
```
tests/rule4_015.yaml => Failed (expected): run_test(80): monitor != good
```
_Note that this test is not considered a failure and the command will produce a zero output._

## WAF validation tests

## Validator self-tests
