# libddwaf release

### v1.0.13 (unstable) - 2021/10/11
- Add support for ruleset format v2.1.
- Update fuzzer.
- Fix addresses with key path missing from ddwaf\_required\_addresses.

### v1.0.12 (unstable) - 2021/10/01
- Add libinjection SQL and XSS rule processors.
- Add support for ruleset format v1.1 (adding is\_sqli and is\_xss operators).
- Improved universal x86\_64 and arm64 builds.
- Added darwin arm64 build.
- Fixed error on corpus generator for fuzzer.

### v1.0.11 (unstable) - 2021/09/16
- Improve contributor onboarding and readme.
- Cross-compile aarch64 static/shared libraries.
- Improve corpus generator for fuzzer.

### v1.0.10 (unstable) - 2021/09/13
- Add license to nuget package.

### v1.0.9 (unstable) - 2021/09/13
- Renamed static windows library to `ddwaf_static`.
- Correctly publish DSO dependencies.
- Add license and notice.
- Add copyright note to source files.
- Add issue and pull-request templates.

### v1.0.8 (unstable) - 2021/09/07
- Removed spdlog dependency.
- Fixed crash on base64encode transformer.
- Fixed crash on compressWhiteSpace transformer.
- Updated and fixed fuzzer.
- Fixed missing static library on windows packages.
- Other minor fixes and improvements.

### v1.0.7 (unstable) - 2021/08/31
- Support for new rule format, using `ddwaf::object`.
- Interface updated with `ddwaf` namespace.
- Removed pass-by-value and return-by-value from interface.
- Removed WAF singleton interface.
- Simplified WAF interface to be handle based and always additive.
- Clarified the ownership of `ddwaf::object` passed to the WAF.
- Removed functionality not supported by the new rule format.
- Added exception catch-all on interface functions to prevent std::terminate.

### v1.0.6 - 2020/10/23
- Convert integers to strings at the input of the WAF
- Report the manifest key of the parameter that we matched in the trigger report
- Fix a bug where we could send reports from a previously reported attack in follow-up executions of the additive API

### v1.0.5 - 2020/10/13
- Fix behavior of @exist on empty list
- Improve the cache bypass logic to only bypass it once per run
- Fix the cache overwrite logic when the bypass resulted in a match

### v1.0.4 - 2020/10/01
- Fix an issue where we wouldn't run on keys if the associtated value was a container in specific encapsulated containers
- Introduce a `numerize` transformer to better handle `Content-Length`

### v1.0.3 - 2020/09/29
- Fix an issue where we wouldn't run on keys if the associtated value was a container

### v1.0.2 - 2020/09/25
- Fix an issue where reports would be generated when no action is triggered
- Fix an issue where only the last step of a flow will trigger a report
- Fix an issue where reports would be incomplete if some rules triggered in previous run of the additive API

### v1.0.1 - 2020/09/23
- Fix a bug where we wouldn't run on keys if the associated value was shorter than a rule's options.min_length

### v1.0 - 2020/08/28
- Introduce transformers to extract CRS targets from the raw URI
- Introduce `removeComments` transformer
- Introduce `@ipMatch` operator

### v0.9.1 (1.0 preview 2) - 2020/08/24
- Introduce modifiers for a rule execution
- Introduce `@exist` operator
- Improve performance of the Additive API
- Reduce the frequency of perf cap check
- Return the detailed performance of the slowest rules
- Introduce allocation helpers
- Other performance optimisations

### v0.9.0 (1.0 preview) - 2020/08/10
- Introduce Additive API
- Introduce expanded initialization format
- Introduce Handle API
- Report performance metrics on each run
- Report the runtime of the slowest rules of each run
- Report the path of a match
- Introduce new transformers
- Rename and shorten the API names
- More...

### v0.7.0 - 2020/06/19
- Fix false positives in libinjection SQL heuristics
- Fix a false positive in libinjection XSS heuristics

### v0.6.1 - 2020/04/03
- When running a rule with multiple parameters, don't stop processing if a parameter is missing
- Add support for the `config` key in the init payload
- Add support for prefixes to operators
- Add a switch through both means to revert the first fix

### v0.6.0 - 2020/03/19
- Replace the clock we were using with a more efficient one
- When processing a multi step rule where a parameter is missing to one step, fail the step instead of ignoring it

### v0.5.1 - 2020/01/10
- Fix a bug where the Compare operators could read one byte after the end of a PWArgs buffer
- Fix a bug where lib injection might read one byte past an internal buffer

### v0.5.0 - 2019/11/15
- Give more control over the safety features to the API

### v0.4.0 - 2019/10/02
- Introduce `@pm` operator

### v0.3.0 - 2019/09/24
- Introduce `@beginsWith`, `@contains`, and `@endsWith` operators
- Cap the memory each RE2 object can use to 512kB

### v0.2.0 - 2019/09/13
- Introduce `powerwaf_initializePowerWAFWithDiag`
- Fix a UTF-8 trucation bug (SQR-8164)
- Cleanup headers
- Improved locking performance

### v0.1.0
- Initial release
