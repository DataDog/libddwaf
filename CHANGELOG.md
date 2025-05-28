# libddwaf release

## v1.25.1 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))
#### Fixes
- Support backwards-incompatible rules through the `rules_compat` key ([#409](https://github.com/DataDog/libddwaf/pull/409))

## v1.25.0 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))
### New features

This new version of `libddwaf` introduces a plethora of new features in order to support new use cases and expand or improve existing ones.

Since this release introduces breaking changes, a new section has been added to the [upgrading guide](https://github.com/DataDog/libddwaf/blob/master/UPGRADING.md#upgrading-from-124x-to-1250).

#### Rule Output Configuration & Attributes

This version expands the mechanisms that rules can use to provide information to the user. Previous versions relied on the generation of events to ensure that the caller had a full picture of the rules, conditions and relevant input data which caused a match. However, this mechanism isn't always suitable as it provides too much information in cases where only a small amount is needed, such as when identifying or extracting request-adjacent metadata. For this reason, rules now have ability to produce attributes in addition to, or instead of, an event as a result of a match. As a consequence of the introduction of attributes, the configuration of rules has been extended with an `output` object, as can be seen below:


```
{
    "output": {
        "keep": (true | false),
        "event": (true | false),
        "attributes": { ... }
    }
}
```
Where:
- `keep`: indicates whether the outcome of the rule must be prioritised, overriding any potential transport sampling (such as trace sampling). This new flag allows the rule writer to ensure that high-frequency / low-value information is only sent opportunistically rather than on every match.
- `event`: enables (`true`) or disables (`false`) event generation, however a rule must always generate either an event or one or more attributes, or both.
- `attributes`: specifies the list of attributes which must be generated and included in the result upon matching the given rule.

The attributes object can follow two possible schemas, the first one defines an attribute with a literal scalar value, as follows:
```
{
    ATTRIBUTE : {
        "value": LITERAL_VALUE
    }
}
```

While the second one defines an attribute containing a scalar value extracted from the data provided within the given context:
```
{
    ATTRIBUTE : {
        "address": ADDRESS,
        "key_path": [ PATH, ... ],
        "transformers": [ TRANSFORMER_ID, ... ]
    }
}
```
_Note that transformers are not supported in this iteration._


#### JWT Decoding Processor

A new processor has been developed to decode and parse targeted JWT tokens. The main purpose of this processor is to generate a new address which can then be analysed by rules in order to identify malicious, invalid, expired or unsafe tokens. As an example, the following _preprocessor_ decodes and parses the `authorization` header into the `server.request.jwt` address:

```json
{
  "id": "processor-001",
  "generator": "jwt_decode",
  "conditions": [],
  "parameters": {
    "mappings": [
      {
        "inputs": [
          {
            "address": "server.request.headers.no_cookies",
            "key_path": [
              "authorization"
            ]
          }
        ],
        "output": "server.request.jwt"
      }
    ]
  },
  "evaluate": true,
  "output": false
}
```

#### Partial Event Obfuscation

To prevent accidental sensitive data leaks, generated events are obfuscated through the use of regular expressions. Until this version, sensitive values were completely replaced with `<Redacted>`, however this new version can perform partial obfuscation of only the relevant values of an unstructured payload. For example, a payload containing `"?token=sensitive-token"` will now be obfuscated as follows: `"?token=<Redacted>"`, preserving more of the semantics of the payload so that the user can better understand the nature of the attack.

This feature provides significant benefit in the case of Exploit Prevention rules, as those tend to contain larger payloads of unstructured data and are often prone to being fully redacted.

_Note that this feature requires the use of the default regular expression for values, overriding it disables partial event obfuscation._

#### Processor Overrides

Last but not least, this release also introduces a new mechanism to override the default configuration of processors, specifically aimed at adding or removing scanners to be used during the process of schema extraction. This can now be done through the `processor_override` top-level configuration key, which has the following schema:

```
{
  ( "processor_override": [
    {
      ( "target": [ PROCESSOR TARGET, ... ], )
      ( "scanners": [ SCANNER_TARGET, ...] )
    },
    ...
  ] )
}
```

Where each `PROCESSOR_TARGET` is an object which specifies the processor to which this override should apply, with the following schema:

```
{
   "id": PROCESSOR_ID,
}
```

Note that in the future, `PROCESSOR_TARGET`, and consequently processors in general, may support tags as well.

Finally, `SCANNER_TARGET` is also an object which specifies the scanners which must be used by this processor, this can be done through their `id` or `tags`, as follows:

```
{
  ( "id": SCANNER_ID, )
  ( "tags": {
    TAG: VALUE,
    ...
  } )
}
```

### Release changelog

#### Changes
- Support for basic processor overrides ([#397](https://github.com/DataDog/libddwaf/pull/397))
- JWT Decoding Processor ([#400](https://github.com/DataDog/libddwaf/pull/400))
- Replace `ddwaf_result` with `ddwaf_object` ([#402](https://github.com/DataDog/libddwaf/pull/402))
- Support for partial event obfuscation ([#403](https://github.com/DataDog/libddwaf/pull/403))
- Support for attribute generation from rules ([#404](https://github.com/DataDog/libddwaf/pull/404))

#### Fixes
- Fix `ddwaf_builder_remove_config` example ([#398](https://github.com/DataDog/libddwaf/pull/398))
- Make SQL comment injection check stricter ([#399](https://github.com/DataDog/libddwaf/pull/399))

#### Miscellaneous
- Enforce CMake 3.5 compatibility ([#395](https://github.com/DataDog/libddwaf/pull/395))
- Update schemas and tests to include validation ([#396](https://github.com/DataDog/libddwaf/pull/396))

## v1.24.1 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))

#### Fixes
- Support single-value arrays when generating fingerprints ([#392](https://github.com/DataDog/libddwaf/pull/392))

#### Miscellaneous
- Benchmarks with PGO ([#383](https://github.com/DataDog/libddwaf/pull/383))

## v1.24.0 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))

### New features
This release only introduces a new builder function which can be used to retrieve the currently loaded configuration paths. This function can be useful for determining if a certain group of configurations is available and / or whether a default configuration is still presently loaded. The new function has the following signature:

```c
uint32_t ddwaf_builder_get_config_paths(ddwaf_builder builder, ddwaf_object *paths, const char *filter, uint32_t filter_len);
```

It can be used to retrieve all loaded paths as follows:
```c
ddwaf_builder builder = ddwaf_builder_init(nullptr);
ddwaf_builder_add_or_update_config(builder, LSTRARG("ASM_DD/default"), &default_config, nullptr);
ddwaf_object_free(&default_config);

ddwaf_object paths;
uint32_t count = ddwaf_builder_get_config_paths(builder, &paths, nullptr, 0);

// count: 1
// paths: [ "ASM_DD/default" ]
```

In addition, the function can also be called with a regular expression to collect only relevant configurations:
```c
ddwaf_builder builder = ddwaf_builder_init(nullptr);
ddwaf_builder_add_or_update_config(builder, LSTRARG("ASM_DD/default"), &default_config, nullptr);
ddwaf_builder_add_or_update_config(builder, LSTRARG("ASM/custom_rules"), &other_config, nullptr);
ddwaf_object_free(&default_config);
ddwaf_object_free(&custom_Rules);

ddwaf_object paths;
uint32_t count = ddwaf_builder_get_config_paths(builder, &paths, LSTRARG("^ASM_DD/.*"));

// count: 1
// paths: [ "ASM_DD/default" ]
```
Note that `LSTRARG` is simply a non-standard macro for converting a literal string into: `<literal>, sizeof(<literal>) - 1`.

More information on how this function must be used can be found [here](https://github.com/DataDog/libddwaf/blob/2cf8025455a1fe8c1169e08abff7ac18a1e56455/include/ddwaf.h#L418).

### Release changelog
#### Changes
- Add function to get list of loaded configuration paths ([#384](https://github.com/DataDog/libddwaf/pull/384))
#### Fixes
- Make builder config const and fix build ([#374](https://github.com/DataDog/libddwaf/pull/374))
#### Miscellaneous
- Add benchmarks using clang-19 ([#380](https://github.com/DataDog/libddwaf/pull/380))

## v1.23.0 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))

### New features

This new version of `libddwaf` introduces the WAF builder, a new mechanism for generating WAF instances through complete or partial configurations. This new mechanism aims to standardise the WAF update process across all WAF users, eliminating the possibility for incomplete or inconsistent implementations. With the introduction of the WAF builder, the `ddwaf_update` function has been deprecated, as the semantics have been drastically changed. More information about the builder can be found ([here](https://github.com/DataDog/libddwaf/blob/master/UPGRADING.md#waf-builder)).

In addition, diagnostics have now been split into warnings and errors to better differentiate those which can indicate a potential issue from those which may indicate a potential, but expected, incompatibility. More information about the diagnostic changes can be found ([here](https://github.com/DataDog/libddwaf/blob/master/UPGRADING.md#warning-and-error-diagnostics)).

Finally, a small but consequential change has been introduced to the endpoint fingerprint generation, which makes the `query` parameter of the postprocessor optional, meaning that fingerprints may be generated without it.

Since this release introduces breaking changes, a new section has been added to the [upgrading guide](https://github.com/DataDog/libddwaf/blob/master/UPGRADING.md#upgrading-from-1220-to-1230).

### Release changelog
#### Changes
- WAF Builder: independent configuration manager to generate WAF instances ([#363](https://github.com/DataDog/libddwaf/pull/363))
- Change endpoint fingerprint query parameter to optional ([#365](https://github.com/DataDog/libddwaf/pull/365))
- Split diagnostics into warnings and errors ([#368](https://github.com/DataDog/libddwaf/pull/368))
- Pass object limits at evaluation time rather than parsing ([#370](https://github.com/DataDog/libddwaf/pull/370))

#### Fixes
- Wrap containers in the ruleset within shared pointers to reduce copies ([#366](https://github.com/DataDog/libddwaf/pull/366))

#### Miscellaneous
- Rename parameter to `raw_configuration` ([#367](https://github.com/DataDog/libddwaf/pull/367))
- Generate coverage at multiple log levels ([#364](https://github.com/DataDog/libddwaf/pull/364))

## v1.22.0 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))
### New features

This new version of `libddwaf` introduces an important new feature: module-based rule evaluation precedence. This new feature ensures that rules are evaluated in a specified order, based on the module they belong to, which specifies the absolute precedence of the rules contained within it, as well as a set of criteria which determines the relative precedence within the module.

Rules within a module are organised based on whether they are in blocking mode or monitoring mode, with the former always having precedence over the latter. In addition, two rules of the same mode are then organised based on whether they belong to the base ruleset (datadog-owned) or the custom ruleset (customer-owned), as some modules give precedence to one over the other.

The modules defined in this version, in their evaluation order, are the following:
- `network-acl`: specifically containing IP denylist rules. In this module, precedence is given to rules within the base ruleset over the custom ruleset. Additionally, this module does not adhere to the user-provided timeout.
- `authentication-acl`: specifically containing user denylist rules. In this module, precedence is given to rules within the base ruleset over the custom ruleset. Additionally, this module does not adhere to the user-provided timeout.
- `custom-acl`: this module contains custom denylist rules, without restriction on the type of inputs targeted. As the name suggests, precedence is given to rules within the custom ruleset.
- `configuration`: this module contains rules for detecting misconfigurations and / or configuration restrictions, giving also precedence to rules within the custom ruleset.
- `business-logic`: containing rules used to identify and / or block business logic events, also giving precedence to rules within the custom ruleset.
- `rasp`: containing exclusively exploit prevention rules. To ensure the effectivenes of exploit prevention rules, this module gives precedence to rules within the base ruleset.
- `waf`:  this module contains rules for detecting attacks exclusively based on the request inputs. Rules within this module are organised by rule type, in what is known as rule collections. This organisation is primarily used to ensure that only a single match of a given type is generated per context, but it also has a marginal impact on the rule evaluation order, as rules are clustered together by type as much as possible. In addition, precedence is given to rules within the custom ruleset rather than the base ruleset.

**Note** that while some modules have "lower" precedence, the reality is that they are often evaluated independently of other modules, as is the case for the `rasp` and `business-logic` modules

Finally, this release also includes a number of fixes and improvements on the exploit prevention heuristics to limit the potential for false positives.

### Release changelog

#### Changes
- Module-based rule evaluation precedence ([#353](https://github.com/DataDog/libddwaf/pull/353))

#### Fixes
- Prevent scheme matches in isolation ([#360](https://github.com/DataDog/libddwaf/pull/360))
- Improve parsing of numbers in SQL tokenizers ([#359](https://github.com/DataDog/libddwaf/pull/359))


## v1.21.0 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))
### New features

This new version of `libddwaf` only introduces one new feature, alongside other fixes and behind-the-scenes changes and improvements.

#### Exploit prevention: Command injection detection
A new operator `cmdi_detector` has been introduced for detecting and blocking command injections. This heuristics builds on the shell injection heuristic in order to detect injections on non-shell APIs, including indirect shell injections. This new operator is part of the exploit prevention feature, so it is meant to be used in combination with targeted instrumentation.

The following example rule takes advantage of the new operator to identify injections originating from request parameters:

```yaml
  - id: rsp-930-005
    name: CMDi Exploit detection
    tags:
      type: cmdi
      category: exploit_detection
      module: rasp
    conditions:
      - parameters:
          resource:
            - address: server.sys.exec.cmd
          params:
            - address: server.request.query
            - address: server.request.body
            - address: server.request.path_params
            - address: grpc.server.request.message
            - address: graphql.server.all_resolvers
            - address: graphql.server.resolver
        operator: cmdi_detector
```
### Release changelog

#### Changes
- Command injection detection operator ([#354](https://github.com/DataDog/libddwaf/pull/354)) ([#356](https://github.com/DataDog/libddwaf/pull/356))

#### Fixes
- Disable a few patterns that caused false positives ([#355](https://github.com/DataDog/libddwaf/pull/355))

#### Miscellaneous
- Fix build on macos-14 ([#349](https://github.com/DataDog/libddwaf/pull/349))
- Support `(min|max)_version` on `verify_rule` utility ([#350](https://github.com/DataDog/libddwaf/pull/350))
- Reorganise tests ([#351](https://github.com/DataDog/libddwaf/pull/351))
- Auto-retry flaky build steps & downgrade to macos-13 ([#357](https://github.com/DataDog/libddwaf/pull/357))

## v1.20.1 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))
#### Changes
- Shell injection for array-based resources ([#333](https://github.com/DataDog/libddwaf/pull/333))

#### Fixes
- Fix logic error on `lfi_detector` for windows and introduce `lfi_detector@v2` ([#346](https://github.com/DataDog/libddwaf/pull/346))

## v1.20.0 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))
### New features
This new version of `libddwaf` introduces a small set of convenience features and expands some of the existing functionality.

#### Fingerprint regeneration
Some of the existing fingerprinting processors have been expanded with the ability to regenerate fingerprints as new data becomes available over subsequent evaluations, specifically:
- The `body` parameter of the `http_endpoint_fingerprint` is now optional.
- All the parameters of the `session_fingerprint` are now optional (`cookies`, `session_id`, `user_id`), however a session fingerprint will only be generated if at least one argument is present.

API users must take into consideration that the same fingerprint may be provided in the `derivatives` section of `ddwaf_result` over subsequent calls, which should override the previously generated one.

#### New \& negated operators
New operators have now been included in this version of `libddwaf`, and some others have been expanded:
- `greater_than`: asserts whether a numeric value in the input data is greater than a specified one.
- `lower_than`: asserts whether a numeric value in the input data is lower than a specified one.
- `exists` for key paths: the `exists` operator is already available to assert the presence of an address, but it has now been expanded to assert the presence of a key path within an address;

In addition, some operators can now be negated, with the following caveats:
- Matches can only be performed on available addresses, as there isn't sufficient information to determine if an address will be provided in a subsequent evaluation. As a consequence, conditions using negated operators can only specify a single input address.
- Due to the above, the negated version of the `exists` operator (`!exists`) can only assert the absence of a key path, rather than an address.

The following are the new negated operators: `!match_regex`, `!phrase_match`, `!exact_match`, `!ip_match`, `!equals` and `!exists`.

#### Min and max version for evaluation primitives
In order to allow for a single ruleset to be used throughout multiple versions of `libddwaf`, while taking advantage of new features and / or changes to the evaluation primitives schema, two new fields have been added:
- `min_version`: this can be used to specify the minimum version of `libddwaf` required to support this evaluation primitive.
- `max_version`: this can be used to specify the maximum version of `libddwaf` required to support this evaluation primitive.

Both fields follow the semantic versioning schema `x.y.z` without a `v` in front nor any subsequent labels or hashes, the minimum allowed version is `0.0.0` and the maximum `999.999.999`. Each new field can be provided in isolation or in combination with its counterpart. 

The evaluation primitives supporting this new fields are: rules, exclusion filters, processors and scanners. An example of a rule using a minimum and maximum version can be seen below:

```yaml
  - id: rsp-930-004
    name: SHi Exploit detection
    tags:
      type: shi
      category: exploit_detection
      module: rasp
    min_version: 1.19.0
    max_version  1.19.999
    conditions:
      - parameters:
          resource:
            - address: server.sys.shell.cmd
          params:
            - address: server.request.query
        operator: shi_detector
```

Finally, when an evaluation primitive doesn't meet the required version criteria, its ID is included in a new diagnostic field called `skipped`, within the relevant section, e.g.
```yaml

rules:
  skipped:
    - rsp-930-004
  loaded: ...
```
#### RASP operator versioning

Finally, in order to distinguish multiple versions of our exploit prevention heuristics, RASP operators can now be versioned. Versioning is done with the following schema: `operator_name@version`, where the operator name is one of the existing RASP operators (`lfi_detector`, `ssrf_detector`, `sqli_detector`, `shi_detector`) and `version` consists of a single digit preceded by a `v`, e.g. `sqli_detector@v2`. 

Operator versioning works as follows:
- When the existing operator version is higher or equal to the required version, the available operator is compatible.
- When the existing operator version is lower than the required version, the operator is incompatible.
- When the operator is incompatible, the rule is silently skipped and added to the `skipped` section of the diagnostics.

In addition, this release includes a new version of the `sqli_detector` operator, specifically `sqli_detector@v2`.

### Release changelog
#### Changes
- Fingerprint regeneration based on availability of optional arguments ([#331](https://github.com/DataDog/libddwaf/pull/331))
- Expand detections per parameter ([#332](https://github.com/DataDog/libddwaf/pull/332))
- Extend exists operator to support key paths and negation ([#334](https://github.com/DataDog/libddwaf/pull/334))
- Negated scalar condition for matchers ([#335](https://github.com/DataDog/libddwaf/pull/335))
- Greater and lower than matchers  ([#336](https://github.com/DataDog/libddwaf/pull/336))
- Support min_version and max_version on evaluation primitives and RASP operator versioning ([#343](https://github.com/DataDog/libddwaf/pull/343))
- Introduce `sqli_detector@v2` ([#343](https://github.com/DataDog/libddwaf/pull/343))
  
#### Fixes
- Fix false positive on SQLi EOL comments ([#330](https://github.com/DataDog/libddwaf/pull/330))

#### Miscellaneous
- Fix many, but not all, clang-tidy complaints ([#339](https://github.com/DataDog/libddwaf/pull/339))
- Set content:write permissions on release job ([#340](https://github.com/DataDog/libddwaf/pull/340))

## v1.19.1 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))
#### Fixes
- Split collections by module ([#328](https://github.com/DataDog/libddwaf/pull/328))

#### Miscellaneous
- Upgrade arm64 runner ([#326](https://github.com/DataDog/libddwaf/pull/326))
- Remove noisy scenarios and add new scenario ([#327](https://github.com/DataDog/libddwaf/pull/327))

## v1.19.0 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))

### New features
This new version of `libddwaf` introduces a multitude of new features in order to support new use cases and expand existing ones.

#### Exploit prevention: Shell injection detection
A new operator `shi_detector` has been introduced for detecting and blocking shell injections, based on input parameters and the final shell code being evaluated. This new operator is part of the exploit prevention feature, so it is meant to be used in combination with targeted instrumentation. 

The following example rule takes advantage of the new operator to identify injections originating from request parameters:

```yaml
  - id: rsp-930-004
    name: SHi Exploit detection
    tags:
      type: shi
      category: exploit_detection
      module: rasp
    conditions:
      - parameters:
          resource:
            - address: server.sys.shell.cmd
          params:
            - address: server.request.query
            - address: server.request.body
            - address: server.request.path_params
            - address: grpc.server.request.message
            - address: graphql.server.all_resolvers
            - address: graphql.server.resolver
        operator: shi_detector
```

#### Attacker \& Request Fingerprinting
This release includes a new family of processors which can be used to generate different fingerprints for a request and / or user, depending on available information:
- `http_endpoint_fingerprint`: this processor generates a fingerprint which uniquely identifies the HTTP endpoint accessed by the request as well as how this endpoint was accessed (i.e. which parameters were used).
- `http_headers_fingerprint`: generates a fingerprint which provides information about the headers used when accessing said HTTP endpoint.
- `http_network_fingerprint`: provides a fingerprint containing some information about the network-related HTTP headers used within the request.
- `session_fingerprint`: this processor generates a specific fingeprint with sufficient information to track a unique session and / or attacker.

#### Suspicious attacker blocking
Suspicious attackers can now be blocked conditionally when they perform a restricted action or an attack. With the combination of custom exclusion filter actions and exclusion data, it is now possible to change the action of a rule dynamically depending on a condition, e.g. all rules could be set to blocking mode if a given IP performs a known attack.

The following exclusion filter, in combination with the provided exclusion data, changes the action of all rules based on the client IP:

```yaml
exclusions:
  - id: suspicious_attacker
    conditions:
      - operator: ip_match
        parameters:
          inputs:
            - address: http.client_ip
          data: ip_data
exclusion_data:
  - id: ip_data
    type: ip_with_expiration
    data:
      - value: 1.2.3.4
        expiration: 0
```

#### Other new features
- New operator `exists`: this new operator can be used to assert the presence of at least one address from a given set of addresses, regardless of their underlying value.
- Rule tagging overrides: rule overrides now allow adding tags to an existing rule, e.g. to provide information about the policy used.
- New function `ddwaf_known_actions`: this new function can be used to obtain a list of the action types which can be triggered given the set of rules and exclusion filters available.

### Release changelog
#### Changes
- Multivariate processors and remove generators ([#298](https://github.com/DataDog/libddwaf/pull/298))
- Custom rule filter actions ([#303](https://github.com/DataDog/libddwaf/pull/303))
- SHA256 hash based on OpenSSL ([#304](https://github.com/DataDog/libddwaf/pull/304))
- Shell injection detection operator ([#308](https://github.com/DataDog/libddwaf/pull/308))
- Limit the number of transformers per rule or input ([#309](https://github.com/DataDog/libddwaf/pull/309))
- Validate redirection location and restrict status codes ([#310](https://github.com/DataDog/libddwaf/pull/310))
- Rule override for adding tags ([#313](https://github.com/DataDog/libddwaf/pull/313))
- Add support for dynamic exclusion filter data ([#316](https://github.com/DataDog/libddwaf/pull/316))
- HTTP Endpoint Fingerprint Processor ([#318](https://github.com/DataDog/libddwaf/pull/318))
- HTTP Header, HTTP Network and Session Fingerprints ([#320](https://github.com/DataDog/libddwaf/pull/320))
- Exists operator and waf.context.event virtual address ([#321](https://github.com/DataDog/libddwaf/pull/321))
- Add function to obtain available actions ([#324](https://github.com/DataDog/libddwaf/pull/324))

#### Fixes
- Transformer fixes and improvements ([#299](https://github.com/DataDog/libddwaf/pull/299))

#### Miscellaneous
- Fix object generator stray container ([#294](https://github.com/DataDog/libddwaf/pull/294))
- Regex tools & benchmark rename ([#290](https://github.com/DataDog/libddwaf/pull/290))
- Order benchmark scenarios ([#300](https://github.com/DataDog/libddwaf/pull/300))
- Upgrade to macos-12 ([#312](https://github.com/DataDog/libddwaf/pull/312))
- Skip disabled rules when generating ruleset ([#314](https://github.com/DataDog/libddwaf/pull/314))
- Update default obfuscator regex ([#317](https://github.com/DataDog/libddwaf/pull/317))

## v1.18.0 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))
This version introduces a new operator `sqli_detector` for the detection of SQL injections. In addition, the ruleset parser has been updated to allow non-string parameter values on action definitions.

#### Changes
- SQL Injection (SQLi) Detection Operator ([#284](https://github.com/DataDog/libddwaf/pull/284))

#### Fixes
- Fix mishandling invalid actions key type ([#286](https://github.com/DataDog/libddwaf/pull/286))
- Convert non-string object types into string during ruleset parsing ([#285](https://github.com/DataDog/libddwaf/pull/285))

#### Miscellaneous
- Use SSE4.1 ceilf when available and add badges to readme ([#288](https://github.com/DataDog/libddwaf/pull/288))
- SQLi Detector Fuzzer and improvements ([#291](https://github.com/DataDog/libddwaf/pull/291))

## v1.17.0 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))

This new version introduces RASP rules and supporting features, including:
- Multivariate operators for the development of complex rules.
- A new operator `lfi_detector` for the detection of local file inclusion (LFI) / path traversal attacks.
- A new operator `ssrf_detector` for the detection of server-side request forgery (SSRF) attacks.
- Better support for rule actions, as well as internal default actions: `block`, `stack_trace` and `extract_schema`.

The [upgrading guide](UPGRADING.md#upgrading-from-116x-to-1170) has also been updated to cover the new breaking changes.

#### Changes
- Multivariate operator support ([#241](https://github.com/DataDog/libddwaf/pull/241))
- Local file inclusion (LFI) operator ([#258](https://github.com/DataDog/libddwaf/pull/258))
- Server-side request forgery (SSRF) detection operator ([#268](https://github.com/DataDog/libddwaf/pull/268))
- Action semantics and related improvements ([#277](https://github.com/DataDog/libddwaf/pull/277))

#### Fixes
- Reduce benchmark noise ([#257](https://github.com/DataDog/libddwaf/pull/257), [#259](https://github.com/DataDog/libddwaf/pull/259), [#260](https://github.com/DataDog/libddwaf/pull/260))
- Add support for old glibc (e.g. RHEL 6) ([#262](https://github.com/DataDog/libddwaf/pull/262))
- Add weak ceilf symbol and definition ([#263](https://github.com/DataDog/libddwaf/pull/263))
- Fix parsing of variadic arguments ([#267](https://github.com/DataDog/libddwaf/pull/267))

#### Miscellaneous
- Update node-16 actions to node-20 ones ([#266](https://github.com/DataDog/libddwaf/pull/266))
- Attempt to build libddwaf on arm64 runner ([#270](https://github.com/DataDog/libddwaf/pull/270))
- Run tests on arm64 ([#271](https://github.com/DataDog/libddwaf/pull/271))
- LFI detector fuzzer ([#274](https://github.com/DataDog/libddwaf/pull/274))
- Remove rpath from linux-musl binary ([#282](https://github.com/DataDog/libddwaf/pull/282))

## v1.17.0-alpha3 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))
#### Changes
- Action semantics and related improvements ([#277](https://github.com/DataDog/libddwaf/pull/277))

#### Miscellaneous
- LFI detector fuzzer ([#274](https://github.com/DataDog/libddwaf/pull/274))

## v1.17.0-alpha2 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))
#### Changes
- Server-side request forgery (SSRF) detection operator ([#268](https://github.com/DataDog/libddwaf/pull/268))

#### Miscellaneous
- Attempt to build libddwaf on arm64 runner ([#270](https://github.com/DataDog/libddwaf/pull/270))
- Run tests on arm64 ([#271](https://github.com/DataDog/libddwaf/pull/271))

## v1.17.0-alpha1 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))
#### Fixes
- Fix parsing of variadic arguments ([#267](https://github.com/DataDog/libddwaf/pull/267))

#### Miscellaneous
- Update node-16 actions to node-20 ones ([#266](https://github.com/DataDog/libddwaf/pull/266))

## v1.17.0-alpha0 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))
#### Fixes
- Add support for old glibc (e.g. RHEL 6) ([#262](https://github.com/DataDog/libddwaf/pull/262))
- Add weak ceilf symbol and definition ([#263](https://github.com/DataDog/libddwaf/pull/263))

#### Changes
- Multivariate operator support ([#241](https://github.com/DataDog/libddwaf/pull/241))
- Local file inclusion (LFI) operator ([#258](https://github.com/DataDog/libddwaf/pull/258))

#### Miscellaneous
- Reduce benchmark noise ([#257](https://github.com/DataDog/libddwaf/pull/257), [#259](https://github.com/DataDog/libddwaf/pull/259), [#260](https://github.com/DataDog/libddwaf/pull/260))

## v1.16.1 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))
### Fixes
- Add support for old glibc (e.g. RHEL 6) ([#262](https://github.com/DataDog/libddwaf/pull/262))
- Add weak ceilf symbol and definition ([#263](https://github.com/DataDog/libddwaf/pull/263))

## v1.16.0 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))
#### Fixes
- Address a libinjection false positive ([#251](https://github.com/DataDog/libddwaf/pull/251))
- Remove a few fingerprints causing false positives ([#252](https://github.com/DataDog/libddwaf/pull/252))
- Fix SSE2 lowercase transformer ([#253](https://github.com/DataDog/libddwaf/pull/253))

#### Changes
- Support ephemeral addresses on processors ([#240](https://github.com/DataDog/libddwaf/pull/240))
- Phrase match: enforce word boundary option ([#256](https://github.com/DataDog/libddwaf/pull/256))

#### Miscellaneous
- Build tools on CI to avoid breaking tool users ([#229](https://github.com/DataDog/libddwaf/pull/229))
- Remove legacy linux builds ([#230](https://github.com/DataDog/libddwaf/pull/230))
- Vendorize re2 and utf8proc ([#231](https://github.com/DataDog/libddwaf/pull/231))
- Refactor cmake scripts and support LTO ([#232](https://github.com/DataDog/libddwaf/pull/232))
- Microbenchmarks ([#242](https://github.com/DataDog/libddwaf/pull/242), [#243](https://github.com/DataDog/libddwaf/pull/243), [#244](https://github.com/DataDog/libddwaf/pull/244), [#245](https://github.com/DataDog/libddwaf/pull/245), [#246](https://github.com/DataDog/libddwaf/pull/246), [#247](https://github.com/DataDog/libddwaf/pull/247), [#248](https://github.com/DataDog/libddwaf/pull/248), [#250](https://github.com/DataDog/libddwaf/pull/250))

## v1.15.1 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))

#### Fixes
- Fix duplicate processor check ([#234](https://github.com/DataDog/libddwaf/pull/234))

## v1.15.0 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))

This new version of the WAF includes the following new features:
- Ephemeral addresses for composite requests
- Naive duplicate address support on input filters
- Required / Optional address diagnostics

The [upgrading guide](UPGRADING.md) has also been updated to cover the new changes.

#### API & Breaking Changes
- Support ephemeral addresses on `ddwaf_run` ([#219](https://github.com/DataDog/libddwaf/pull/219))
- Rename `ddwaf_required_addresses` to `ddwaf_known_addresses` ([#221](https://github.com/DataDog/libddwaf/pull/221))

#### Fixes
- Schema extraction scanners: reduce false positives on arrays ([#220](https://github.com/DataDog/libddwaf/pull/220))

#### Changes
- Ephemeral addresses for rules & exclusion filters ([#219](https://github.com/DataDog/libddwaf/pull/219))([#224](https://github.com/DataDog/libddwaf/pull/224))
- Address diagnostics ([#221](https://github.com/DataDog/libddwaf/pull/221))
- Naive duplicate address support on input/object filters ([#222](https://github.com/DataDog/libddwaf/pull/222))

#### Miscellaneous
- Update nuget packaging to use new musl linux binaries ([#217](https://github.com/DataDog/libddwaf/pull/217))
- Validator improvements  ([#225](https://github.com/DataDog/libddwaf/pull/225))
- Use `fmt::format` for logging and vendorize some dependencies within `src/` ([#226](https://github.com/DataDog/libddwaf/pull/226))
- Reduce linux binary size and fix some flaky tests ([#227](https://github.com/DataDog/libddwaf/pull/227))

## v1.14.0 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))

This release of the WAF includes the following new features:
- Schema data classification through the use of scanners.
- A vectorized version of the `lowercase` transformer using SSE2.
- Generalized processors which are evaluated before or after filters and rules based on their outcome.
- Optimizations to avoid unnecessary rule and filter evaluation.
- Many other quality of life, correctness and performance improvements

#### API & Breaking Changes
- Rename `preprocessor` top-level key to `processor` ([#209](https://github.com/DataDog/libddwaf/pull/209))

#### Fixes
- Fix missing top-level key for processor diagnostics ([#209](https://github.com/DataDog/libddwaf/pull/209))

#### Changes
- SSE2 lowercase transformer ([#195](https://github.com/DataDog/libddwaf/pull/195))
- Reduce schema extraction limits ([#208](https://github.com/DataDog/libddwaf/pull/208))
- Skip rule and filter evaluation when no new rule targets exist ([#207](https://github.com/DataDog/libddwaf/pull/207))
- Refactor preprocessors into preprocessors and postprocessors ([#209](https://github.com/DataDog/libddwaf/pull/209))
- Convert float to (un)signed within the parsing stage ([#210](https://github.com/DataDog/libddwaf/pull/210))
- Scanners for schema scalar classification ([#211](https://github.com/DataDog/libddwaf/pull/211))
- Remove ptr typedefs ([#212](https://github.com/DataDog/libddwaf/pull/212))
- Indexer abstraction to encapsulate rule and scanner search and storage ([#213](https://github.com/DataDog/libddwaf/pull/213))

## v1.13.1 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))

#### Changes
- Allow conversions between signed/unsigned types during parsing ([#205](https://github.com/DataDog/libddwaf/pull/205))

## v1.13.0 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))

This new version of the WAF includes the following new features:
- Schema extraction preprocessor
- New and improved universal linux buids, including support for i386 and armv7
- `float` and `null` types
- Equals operator for arbitrary type equality comparison within conditions
- Many other quality of life, correctness and performance improvements

The [upgrading guide](UPGRADING.md) has also been updated to cover the new changes.

#### API & Breaking Changes
- Add object types `DDWAF_OBJ_FLOAT` and `DDWAF_OBJ_NULL` ([#197](https://github.com/DataDog/libddwaf/pull/197))
- Add `double` field `f64` in `ddwaf_object` ([#197](https://github.com/DataDog/libddwaf/pull/197))
- Add `ddwaf_object_null`, `ddwaf_object_float`and `ddwaf_object_get_float` ([#197](https://github.com/DataDog/libddwaf/pull/197))
- Rename `ddwaf_object_signed` to `ddwaf_object_string_from_signed` ([#197](https://github.com/DataDog/libddwaf/pull/197))
- Rename `ddwaf_object_unsigned` to `ddwaf_object_string_from_unsigned` ([#197](https://github.com/DataDog/libddwaf/pull/197))
- Rename `ddwaf_object_signed_force` to `ddwaf_object_signed`([#197](https://github.com/DataDog/libddwaf/pull/197))
- Rename `ddwaf_object_unsigned_force` to `ddwaf_object_unsigned`([#197](https://github.com/DataDog/libddwaf/pull/197))
- Add `derivatives` field to `ddwaf_result` for output objects generated through preprocessors ([#182](https://github.com/DataDog/libddwaf/pull/182))

#### Changes
- Encapsulate conditions within expressions ([#192](https://github.com/DataDog/libddwaf/pull/192))
- Equals operator and arbitrary operator type support ([#194](https://github.com/DataDog/libddwaf/pull/194))
- Float and null type support ([#197](https://github.com/DataDog/libddwaf/pull/197))
- Schema Extraction Preprocessor ([#182](https://github.com/DataDog/libddwaf/pull/182))([#202](https://github.com/DataDog/libddwaf/pull/202))

#### Miscellaneous
- Minor improvements ([#193](https://github.com/DataDog/libddwaf/pull/193))
- Rename operation to matcher ([#196](https://github.com/DataDog/libddwaf/pull/196))
- Fix coverage ([#199](https://github.com/DataDog/libddwaf/pull/199))
- Linux musl/libc++ builds using alpine-based sysroots and llvm16 ([#198](https://github.com/DataDog/libddwaf/pull/198))([#200](https://github.com/DataDog/libddwaf/pull/200))([#201](https://github.com/DataDog/libddwaf/pull/201))


## v1.12.0 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))
#### Changes
- Per-input transformers support on exclusion filter conditions ([#177](https://github.com/DataDog/libddwaf/pull/177))
- Read-only transformers ([#178](https://github.com/DataDog/libddwaf/pull/178))([#185](https://github.com/DataDog/libddwaf/pull/185))([#190](https://github.com/DataDog/libddwaf/pull/190))
- Rule filter bypass / monitor mode support ([#184](https://github.com/DataDog/libddwaf/pull/184))([#188](https://github.com/DataDog/libddwaf/pull/188))

#### Miscellaneous
- Object schemas ([#174](https://github.com/DataDog/libddwaf/pull/174))
- Simple IP Match Benchmark ([#176](https://github.com/DataDog/libddwaf/pull/176))
- Remove Manifest ([#179](https://github.com/DataDog/libddwaf/pull/179))
- Reduce build parallelism ([#183](https://github.com/DataDog/libddwaf/pull/183))
- Change standard to C++20 ([#186](https://github.com/DataDog/libddwaf/pull/186))

## v1.11.0 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))
#### API & Breaking Changes
- Full ruleset parsing diagnostics ([#161](https://github.com/DataDog/libddwaf/pull/161))
- Event result as `ddwaf_object` ([#162](https://github.com/DataDog/libddwaf/pull/162))
- Replace `ddwaf_result.actions` with a `ddwaf_object` array ([#165](https://github.com/DataDog/libddwaf/pull/165))

#### Changes
- Add logging and remove dead code ([#169](https://github.com/DataDog/libddwaf/pull/169))
- Support for per-input transformers ([#170](https://github.com/DataDog/libddwaf/pull/170))

#### Miscellaneous
- Multithreaded fuzzer ([#166](https://github.com/DataDog/libddwaf/pull/166))
- Fix benchmark, test output and update ruleset to 1.7.0 ([#171](https://github.com/DataDog/libddwaf/pull/171))
- Validator: add support for per-directory tests and ruleset ([#172](https://github.com/DataDog/libddwaf/pull/172))
- Rename examples directory to tools ([#173](https://github.com/DataDog/libddwaf/pull/173))
- Update ruleset to 1.7.1 ([#173](https://github.com/DataDog/libddwaf/pull/173))
- Refactor and simplify tools to reduce code duplication ([#173](https://github.com/DataDog/libddwaf/pull/173))

## v1.10.0 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))
#### Changes
- Add all rule tags to event ([#160](https://github.com/DataDog/libddwaf/pull/160))

## v1.9.0 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))
#### Changes
- Remove a libinjection signature ([#145](https://github.com/DataDog/libddwaf/pull/145))
- Priority collection, rule and filter simplification ([#150](https://github.com/DataDog/libddwaf/pull/150))
- Improve allocation / deallocation performance within the context using a `context_allocator` ([#151](https://github.com/DataDog/libddwaf/pull/151))
- Longest rule data expiration takes precedence for `ip_match` and `exact_match` operators ([#152](https://github.com/DataDog/libddwaf/pull/152))
- Custom rules support ([#154](https://github.com/DataDog/libddwaf/pull/154))
- Add vdso support for aarch64 ([#157](https://github.com/DataDog/libddwaf/pull/157))

#### Miscellaneous
- Upgrade CodeQL Github Action to v2 ([#144](https://github.com/DataDog/libddwaf/pull/144))
- Fix broken builds ([#147](https://github.com/DataDog/libddwaf/pull/147))
- Benchmark: context destroy fixture ([#148](https://github.com/DataDog/libddwaf/pull/148))
- Remove unused json rule files and vendorise aho-corasick submodule ([#153](https://github.com/DataDog/libddwaf/pull/153))
- Cancel jobs in progress ([#158](https://github.com/DataDog/libddwaf/pull/158))

## v1.8.2 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))
#### Changes
- Use raw pointers instead of shared pointers for rule targets ([#141](https://github.com/DataDog/libddwaf/pull/141))

#### Fixes
- Relax rule override restrictions ([#140](https://github.com/DataDog/libddwaf/pull/140))
- Initialise `ruleset_info` on invalid input ([#142](https://github.com/DataDog/libddwaf/pull/142))

## v1.8.1 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))
#### Fixes
- Return `NULL` handle when incorrect version or empty rules provided to `ddwaf_init` ([#139](https://github.com/DataDog/libddwaf/pull/139))

## v1.8.0 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics))
#### API \& Breaking Changes
- Add `ddwaf_update` for all-in-one ruleset updates ([#138](https://github.com/DataDog/libddwaf/pull/138))
- Remove `ddwaf_required_rule_data_ids` ([#138](https://github.com/DataDog/libddwaf/pull/138))
- Remove `ddwaf_update_rule_data` ([#138](https://github.com/DataDog/libddwaf/pull/138))
- Remove `ddwaf_toggle_rules` ([#138](https://github.com/DataDog/libddwaf/pull/138))

#### Changes
- Add WAF Builder ([#138](https://github.com/DataDog/libddwaf/pull/138))

## v1.7.0  ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics)) - 2023/02/06
#### Changes
- Handle lifetime extension ([#135](https://github.com/DataDog/libddwaf/pull/135))
- Create macos universal binary ([#136](https://github.com/DataDog/libddwaf/pull/136))

## v1.6.2  ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics)) - 2023/01/26
#### Changes
- Add boolean getter ([#132](https://github.com/DataDog/libddwaf/pull/132))
- Add support for converting string to bool in parameter bool cast operator ([#133](https://github.com/DataDog/libddwaf/pull/133))
- Add parameter `int64_t` cast operator ([#133](https://github.com/DataDog/libddwaf/pull/133))
- Add support for `enabled` flag on ruleset parser ([#133](https://github.com/DataDog/libddwaf/pull/133))

#### Fixes
- Replace `isdigit` with custom version due to windows locale-dependence ([#133](https://github.com/DataDog/libddwaf/pull/133))
- Minor fixes and parsing improvements ([#133](https://github.com/DataDog/libddwaf/pull/133))

## v1.6.1 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics)) - 2023/01/17

#### Miscellaneous
- Add SHA256 to packages ([#128](https://github.com/DataDog/libddwaf/pull/128))
- Automatic draft release on tag ([#129](https://github.com/DataDog/libddwaf/pull/129))

## v1.6.0 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics)) - 2023/01/10

#### Changes
- Exclusion filters: targets and conditions ([#110](https://github.com/DataDog/libddwaf/pull/110))
- Exclusion filters: inputs ([#117](https://github.com/DataDog/libddwaf/pull/117))
- Add ID to exclusion filters ([#120](https://github.com/DataDog/libddwaf/pull/120))
- Rework path trie for exclusion ([#122](https://github.com/DataDog/libddwaf/pull/122))
- Priority collections ([#123](https://github.com/DataDog/libddwaf/pull/123))
- Support for glob component and arrays on object filter ([#124](https://github.com/DataDog/libddwaf/pull/124))

#### Miscellaneous
- Experiment building libddwaf on the oldest available macos target ([#111](https://github.com/DataDog/libddwaf/pull/111))
- Strip libddwaf.a for darwin/linux release ([#107](https://github.com/DataDog/libddwaf/pull/107))
- linux/aarch64: add missing libunwind.a artefact ([#109](https://github.com/DataDog/libddwaf/pull/109))
- Add option to prevent loading test targets ([#108](https://github.com/DataDog/libddwaf/pull/108))
- Upgrade deprecated actions ([#114](https://github.com/DataDog/libddwaf/pull/114))
- Include mac arm binaries in nuget ([#115](https://github.com/DataDog/libddwaf/pull/115))
- Run clang tidy / format on CI ([#116](https://github.com/DataDog/libddwaf/pull/116))
- Exclusion filters on fuzzer ([#118](https://github.com/DataDog/libddwaf/pull/118))

## v1.5.1 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics)) - 2022/09/22

#### API \& Breaking Changes
- Add `ddwaf_required_rule_data_ids` to obtain the rule data IDs defined in the ruleset ([#104](https://github.com/DataDog/libddwaf/pull/104))

#### Miscellaneous
- GTest `ddwaf_result` validators ([#102](https://github.com/DataDog/libddwaf/pull/102))
- Replace `std::optional::value()` with `std::optional::operator*()` ([#105](https://github.com/DataDog/libddwaf/pull/105))
- Add new and missing exports ([#106](https://github.com/DataDog/libddwaf/pull/106))

## v1.5.0 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics)) - 2022/09/08

#### API \& Breaking Changes
- Remove `ddwaf_version`, `ddwaf_get_version` now returns a version string ([#89](https://github.com/DataDog/libddwaf/pull/89))
- Move free function from `ddwaf_context_init` to `ddwaf_config` ([#89](https://github.com/DataDog/libddwaf/pull/89))
- Add `ddwaf_result.actions` struct containing a `char*` array and its size ([#91](https://github.com/DataDog/libddwaf/pull/91))
- Add `ddwaf_update_rule_data` ([#91](https://github.com/DataDog/libddwaf/pull/91))
- Remote `DDWAF_BLOCK` ([#91](https://github.com/DataDog/libddwaf/pull/91))
- Rename `DDWAF_GOOD` to `DDWAF_OK` ([#92](https://github.com/DataDog/libddwaf/pull/92))
- Rename `DDWAF_MONITOR` to `DDWAF_MATCH` ([#92](https://github.com/DataDog/libddwaf/pull/92))
- Deanonymize nested structs ([#97](https://github.com/DataDog/libddwaf/pull/97))
- Add `ddwaf_object_bool` for backwards-compatible support for boolean `ddwaf_object` ([#99](https://github.com/DataDog/libddwaf/pull/99))
- Add `ddwaf_toggle_rules` to enable or disable rules at runtime ([#99](https://github.com/DataDog/libddwaf/pull/99))

#### Changes
- Add `unicode_normalize` transformer ([#82](https://github.com/DataDog/libddwaf/pull/82))
- Remove `PWRetriever`, `PWArgsWrapper`, `Iterator` and `ArgsIterator` ([#77](https://github.com/DataDog/libddwaf/pull/77))
- Add `ddwaf::object_store` to manage all targets and objects provided to the WAF ([#77](https://github.com/DataDog/libddwaf/pull/77))
- Add `ddwaf::value_iterator` for object value traversal ([#77](https://github.com/DataDog/libddwaf/pull/77))
- Add `ddwaf::key_iterator` for object key traversal ([#77](https://github.com/DataDog/libddwaf/pull/77))
- Simplify target manifest ([#78](https://github.com/DataDog/libddwaf/pull/78))
- Remove input object validation ([#85](https://github.com/DataDog/libddwaf/pull/85))
- Merge `PWAdditive` and `PWProcessor`and rename to `ddwaf::context` ([#89](https://github.com/DataDog/libddwaf/pull/89))
- Rename `PowerWAF` to `ddwaf::waf` ([#89](https://github.com/DataDog/libddwaf/pull/89))
- Add `ddwaf::timer` to abstract deadline ([#89](https://github.com/DataDog/libddwaf/pull/89))
- Simplify rule processors ([#89](https://github.com/DataDog/libddwaf/pull/89))
- Add `ip_match` operator and tests ([#87](https://github.com/DataDog/libddwaf/pull/87))
- Refactor ip handling into `ip_utils` ([#87](https://github.com/DataDog/libddwaf/pull/87))
- Add `exact_match` operator and tests ([#87](https://github.com/DataDog/libddwaf/pull/87))
- Rename existing rule processors to more closely resemble their operator name ([#87](https://github.com/DataDog/libddwaf/pull/87))
- Rename `IPWRuleProcessor` to `rule_processor_base` ([#87](https://github.com/DataDog/libddwaf/pull/87))
- Add support for per-rule `on_match` array in ruleset ([#91](https://github.com/DataDog/libddwaf/pull/91))
- Add optional `on_match` to JSON event format ([#91](https://github.com/DataDog/libddwaf/pull/91))
- Remove `PWRetManager` and `MatchGatherer` ([#91](https://github.com/DataDog/libddwaf/pull/91))
- Add `ddwaf::event` to collect all relevant rule match data in one structure ([#91](https://github.com/DataDog/libddwaf/pull/91))
- Add `ddwaf::event_serializer` for JSON event ([#91](https://github.com/DataDog/libddwaf/pull/91))
- Update processors to use `std::string_view` rather than `char *` and length ([#91](https://github.com/DataDog/libddwaf/pull/91))
- Add `ddwaf::timeout_exception` to avoid error code propagation ([#91](https://github.com/DataDog/libddwaf/pull/91))
- Disable the `1)c` libinjection fingerprint ([#94](https://github.com/DataDog/libddwaf/pull/94))
- Configurable rule data ([#96](https://github.com/DataDog/libddwaf/pull/96))

#### Fixes
- Timeout error propagation ([#89](https://github.com/DataDog/libddwaf/pull/89))
- Pass object limits configuration to iterators ([#89](https://github.com/DataDog/libddwaf/pull/89))
- Apply string limits ([#89](https://github.com/DataDog/libddwaf/pull/89))
- Fix missing exports ([#101](https://github.com/DataDog/libddwaf/pull/101))

#### Miscellaneous
- Add `utf8proc` license ([#84](https://github.com/DataDog/libddwaf/pull/84))
- Add codecov support ([#86](https://github.com/DataDog/libddwaf/pull/86))
- Add CODEOWNERS  ([#88](https://github.com/DataDog/libddwaf/pull/88))
- Add `benchmerge` to merge multiple benchmark results ([#85](https://github.com/DataDog/libddwaf/pull/85))
- Update ruleset version for testing to 1.3.2 ([#101](https://github.com/DataDog/libddwaf/pull/101))
- Fix missing build flags from `utf8proc` build ([#100](https://github.com/DataDog/libddwaf/pull/100))

## v1.5.0-rc0 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics)) - 2022/09/02

#### API \& Breaking Changes
- Add `ddwaf_object_bool` for backwards-compatible support for boolean `ddwaf_object` ([#99](https://github.com/DataDog/libddwaf/pull/99))
- Add `ddwaf_toggle_rules` to enable or disable rules at runtime ([#99](https://github.com/DataDog/libddwaf/pull/99))

#### Fixes
- Fix missing exports ([#101](https://github.com/DataDog/libddwaf/pull/101))

#### Miscellaneous
- Update ruleset version for testing to 1.3.2 ([#101](https://github.com/DataDog/libddwaf/pull/101))
- Fix missing build flags from `utf8proc` build ([#100](https://github.com/DataDog/libddwaf/pull/100))

## v1.5.0-alpha1 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics)) - 2022/08/30

#### API \& Breaking Changes
- Deanonymize nested structs ([#97](https://github.com/DataDog/libddwaf/pull/97))

#### Changes
- Disable the `1)c` libinjection fingerprint ([#94](https://github.com/DataDog/libddwaf/pull/94))
- Configurable rule data ([#96](https://github.com/DataDog/libddwaf/pull/96))

## v1.5.0-alpha0 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics)) - 2022/08/04

#### API \& Breaking Changes
- Remove `ddwaf_version`, `ddwaf_get_version` now returns a version string ([#89](https://github.com/DataDog/libddwaf/pull/89))
- Move free function from `ddwaf_context_init` to `ddwaf_config` ([#89](https://github.com/DataDog/libddwaf/pull/89))
- Add `ddwaf_result.actions` struct containing a `char*` array and its size ([#91](https://github.com/DataDog/libddwaf/pull/91))
- Add dummy `ddwaf_update_rule_data` for future use ([#91](https://github.com/DataDog/libddwaf/pull/91))
- Remote `DDWAF_BLOCK` ([#91](https://github.com/DataDog/libddwaf/pull/91))
- Rename `DDWAF_GOOD` to `DDWAF_OK` ([#92](https://github.com/DataDog/libddwaf/pull/92))
- Rename `DDWAF_MONITOR` to `DDWAF_MATCH` ([#92](https://github.com/DataDog/libddwaf/pull/92))

#### Changes
- Add `unicode_normalize` transformer ([#82](https://github.com/DataDog/libddwaf/pull/82))
- Remove `PWRetriever`, `PWArgsWrapper`, `Iterator` and `ArgsIterator` ([#77](https://github.com/DataDog/libddwaf/pull/77))
- Add `ddwaf::object_store` to manage all targets and objects provided to the WAF ([#77](https://github.com/DataDog/libddwaf/pull/77))
- Add `ddwaf::value_iterator` for object value traversal ([#77](https://github.com/DataDog/libddwaf/pull/77))
- Add `ddwaf::key_iterator` for object key traversal ([#77](https://github.com/DataDog/libddwaf/pull/77))
- Simplify target manifest ([#78](https://github.com/DataDog/libddwaf/pull/78))
- Remove input object validation ([#85](https://github.com/DataDog/libddwaf/pull/85))
- Merge `PWAdditive` and `PWProcessor`and rename to `ddwaf::context` ([#89](https://github.com/DataDog/libddwaf/pull/89))
- Rename `PowerWAF` to `ddwaf::waf` ([#89](https://github.com/DataDog/libddwaf/pull/89))
- Add `ddwaf::timer` to abstract deadline ([#89](https://github.com/DataDog/libddwaf/pull/89))
- Simplify rule processors ([#89](https://github.com/DataDog/libddwaf/pull/89))
- Add `ip_match` operator and tests ([#87](https://github.com/DataDog/libddwaf/pull/87))
- Refactor ip handling into `ip_utils` ([#87](https://github.com/DataDog/libddwaf/pull/87))
- Add `exact_match` operator and tests ([#87](https://github.com/DataDog/libddwaf/pull/87))
- Rename existing rule processors to more closely resemble their operator name ([#87](https://github.com/DataDog/libddwaf/pull/87))
- Rename `IPWRuleProcessor` to `rule_processor_base` ([#87](https://github.com/DataDog/libddwaf/pull/87))
- Add support for per-rule `on_match` array in ruleset ([#91](https://github.com/DataDog/libddwaf/pull/91))
- Add optional `on_match` to JSON event format ([#91](https://github.com/DataDog/libddwaf/pull/91))
- Remove `PWRetManager` and `MatchGatherer` ([#91](https://github.com/DataDog/libddwaf/pull/91))
- Add `ddwaf::event` to collect all relevant rule match data in one structure ([#91](https://github.com/DataDog/libddwaf/pull/91))
- Add `ddwaf::event_serializer` for JSON event ([#91](https://github.com/DataDog/libddwaf/pull/91))
- Update processors to use `std::string_view` rather than `char *` and length ([#91](https://github.com/DataDog/libddwaf/pull/91))
- Add `ddwaf::timeout_exception` to avoid error code propagation ([#91](https://github.com/DataDog/libddwaf/pull/91))

#### Fixes
- Timeout error propagation ([#89](https://github.com/DataDog/libddwaf/pull/89))
- Pass object limits configuration to iterators ([#89](https://github.com/DataDog/libddwaf/pull/89))
- Apply string limits ([#89](https://github.com/DataDog/libddwaf/pull/89))

#### Miscellaneous
- Add `utf8proc` license ([#84](https://github.com/DataDog/libddwaf/pull/84))
- Add codecov support ([#86](https://github.com/DataDog/libddwaf/pull/86))
- Add CODEOWNERS  ([#88](https://github.com/DataDog/libddwaf/pull/88))
- Add `benchmerge` to merge multiple benchmark results ([#85](https://github.com/DataDog/libddwaf/pull/85))

## v1.4.0 ([unstable](https://github.com/DataDog/libddwaf/blob/master/README.md#versioning-semantics)) - 2022/06/29
- Correct nuget url ([#68](https://github.com/DataDog/libddwaf/pull/68))
- Only take params ownership when needed ([#69](https://github.com/DataDog/libddwaf/pull/69))
- WAF Benchmark Utility ([#70](https://github.com/DataDog/libddwaf/pull/70))
- WAF Validator ([#74](https://github.com/DataDog/libddwaf/pull/74))
- Make libinjection look for backticks ([#80](https://github.com/DataDog/libddwaf/pull/80))
- Add version semantic and unstable release information  ([#81](https://github.com/DataDog/libddwaf/pull/81))

## v1.3.0 (unstable) - 2022/04/04
- WAF event obfuscator.
- Add obfuscator configuration to `ddwaf_config`.
- Changes to limits in `ddwaf_config`:
  - Rename `maxArrayLength` to `limits.max_container_size`.
  - Rename `maxMapDepth` to `limits.max_container_depth`.
  - Add `limits.max_string_length`, currently unused.
  - All limits are now `uint32`.
  - Relevant macros renamed accordingly.

## v1.2.1 (unstable) - 2022/03/17
- Fix issue on ruleset error map reallocation causing cached pointer invalidation.
- Add check for empty input map on parser.
- Update github actions windows build VM to windows-2019.

## v1.2.0 (unstable) - 2022/03/16
- Remove metrics collector.
- Add `total_runtime` to `ddwaf_result`.
- Fix issue when reporting timeouts.

## v1.1.0 (unstable) - 2022/03/09
- Add `ddwaf_object` getters.
- Provide ruleset parsing diagnostics on `ddwaf_init`.
- Add support for metrics collection on `ddwaf_run`.
- Add `keys_only` transformer.
- Improve support for older platforms.
- Remove indirection and reduce string operations when processing flows.
- Refactor input verification.
- Remove deprecated features.

## v1.0.18 (unstable) - 2022/02/16
- Add arm64 build to nuget package.
- Upgrade RE2 to 2022-02-01.

## v1.0.17 (unstable) - 2022/01/24
- Add missing libunwind to x86\_64 linux build.
- Fix potential integer overflow in `DDWAF_LOG_HELPER`.
- Add missing shared mingw64 build.
- Add example tool to run the WAF on a single rule with multiple test vectors.

## v1.0.16 (unstable) - 2021/12/15
- Fix duplicate matches in output ([#36](https://github.com/DataDog/libddwaf/issues/36))

## v1.0.15 (unstable) - 2021/12/07
- Support `min_length` option on `regex_match` operator.
- Remove `DDWAF_ERR_TIMEOUT` and update value of other errors.
- Add timeout field to `ddwaf_result`.
- Remove action field from `ddwaf_result`.
- Support MacOS 10.9.
- Minor CMake compatibility improvements.

## v1.0.14 (unstable) - 2021/10/26
- WAF output now conforms to the appsec event format v1.0.0.
- Add schema for output validation.
- Remove zip package generation.
- Minor improvements.

## v1.0.13 (unstable) - 2021/10/11
- Add support for ruleset format v2.1.
- Update fuzzer.
- Fix addresses with key path missing from ddwaf\_required\_addresses.
- Improve ruleset parsing logging.

## v1.0.12 (unstable) - 2021/10/01
- Add libinjection SQL and XSS rule processors.
- Add support for ruleset format v1.1 (adding is\_sqli and is\_xss operators).
- Improved universal x86\_64 and arm64 builds.
- Added darwin arm64 build.
- Fixed error on corpus generator for fuzzer.

## v1.0.11 (unstable) - 2021/09/16
- Improve contributor onboarding and readme.
- Cross-compile aarch64 static/shared libraries.
- Improve corpus generator for fuzzer.

## v1.0.10 (unstable) - 2021/09/13
- Add license to nuget package.

## v1.0.9 (unstable) - 2021/09/13
- Renamed static windows library to `ddwaf_static`.
- Correctly publish DSO dependencies.
- Add license and notice.
- Add copyright note to source files.
- Add issue and pull-request templates.

## v1.0.8 (unstable) - 2021/09/07
- Removed spdlog dependency.
- Fixed crash on base64encode transformer.
- Fixed crash on compressWhiteSpace transformer.
- Updated and fixed fuzzer.
- Fixed missing static library on windows packages.
- Other minor fixes and improvements.

## v1.0.7 (unstable) - 2021/08/31
- Support for new rule format, using `ddwaf::object`.
- Interface updated with `ddwaf` namespace.
- Removed pass-by-value and return-by-value from interface.
- Removed WAF singleton interface.
- Simplified WAF interface to be handle based and always additive.
- Clarified the ownership of `ddwaf::object` passed to the WAF.
- Removed functionality not supported by the new rule format.
- Added exception catch-all on interface functions to prevent std::terminate.

## v1.0.6 - 2020/10/23
- Convert integers to strings at the input of the WAF
- Report the manifest key of the parameter that we matched in the trigger report
- Fix a bug where we could send reports from a previously reported attack in follow-up executions of the additive API

## v1.0.5 - 2020/10/13
- Fix behavior of @exist on empty list
- Improve the cache bypass logic to only bypass it once per run
- Fix the cache overwrite logic when the bypass resulted in a match

## v1.0.4 - 2020/10/01
- Fix an issue where we wouldn't run on keys if the associtated value was a container in specific encapsulated containers
- Introduce a `numerize` transformer to better handle `Content-Length`

## v1.0.3 - 2020/09/29
- Fix an issue where we wouldn't run on keys if the associtated value was a container

## v1.0.2 - 2020/09/25
- Fix an issue where reports would be generated when no action is triggered
- Fix an issue where only the last step of a flow will trigger a report
- Fix an issue where reports would be incomplete if some rules triggered in previous run of the additive API

## v1.0.1 - 2020/09/23
- Fix a bug where we wouldn't run on keys if the associated value was shorter than a rule's options.min_length

## v1.0 - 2020/08/28
- Introduce transformers to extract CRS targets from the raw URI
- Introduce `removeComments` transformer
- Introduce `@ipMatch` operator

## v0.9.1 (1.0 preview 2) - 2020/08/24
- Introduce modifiers for a rule execution
- Introduce `@exist` operator
- Improve performance of the Additive API
- Reduce the frequency of perf cap check
- Return the detailed performance of the slowest rules
- Introduce allocation helpers
- Other performance optimisations

## v0.9.0 (1.0 preview) - 2020/08/10
- Introduce Additive API
- Introduce expanded initialization format
- Introduce Handle API
- Report performance metrics on each run
- Report the runtime of the slowest rules of each run
- Report the path of a match
- Introduce new transformers
- Rename and shorten the API names
- More...

## v0.7.0 - 2020/06/19
- Fix false positives in libinjection SQL heuristics
- Fix a false positive in libinjection XSS heuristics

## v0.6.1 - 2020/04/03
- When running a rule with multiple parameters, don't stop processing if a parameter is missing
- Add support for the `config` key in the init payload
- Add support for prefixes to operators
- Add a switch through both means to revert the first fix

## v0.6.0 - 2020/03/19
- Replace the clock we were using with a more efficient one
- When processing a multi step rule where a parameter is missing to one step, fail the step instead of ignoring it

## v0.5.1 - 2020/01/10
- Fix a bug where the Compare operators could read one byte after the end of a PWArgs buffer
- Fix a bug where lib injection might read one byte past an internal buffer

## v0.5.0 - 2019/11/15
- Give more control over the safety features to the API

## v0.4.0 - 2019/10/02
- Introduce `@pm` operator

## v0.3.0 - 2019/09/24
- Introduce `@beginsWith`, `@contains`, and `@endsWith` operators
- Cap the memory each RE2 object can use to 512kB

## v0.2.0 - 2019/09/13
- Introduce `powerwaf_initializePowerWAFWithDiag`
- Fix a UTF-8 trucation bug (SQR-8164)
- Cleanup headers
- Improved locking performance

## v0.1.0
- Initial release
