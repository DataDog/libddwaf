# Operator Reference

Libddwaf supports a mixture of low-level “scalar” match operators and higher-level detectors that encapsulate complex heuristics. This document enumerates each of the available operators, together with the arguments they expect.

---

## Scalar match operators

These operators compare request data against literal values, numerical thresholds, or pattern libraries. They are implemented in `src/matcher/*` and are available both in positive form (`operator`) and negated form (`!operator`) unless noted.

### `equals`
- **Purpose:** Compare a value to a literal.
- **Arguments:**  
  - `type`: `"string"`, `"boolean"`, `"unsigned"`, `"signed"`, or `"float"`.  
  - `value`: literal to compare against.  
  - `delta` (optional, floats only): tolerance when comparing floating point numbers.
- **Notes:** Supports negation (`!equals`) which must be scoped to a single address and / or key path.

### `exact_match`
- **Purpose:** Match against a list of exact strings.
- **Arguments:**  
  - `inputs`.  
  - Either `list` (array of strings) or `data` (rules-data identifier, mutually exclusive).
- **Notes:** Works on string inputs only; negated form `!exact_match` is supported.

### `greater_than`
- **Purpose:** Numeric greater-than comparison.
- **Arguments:**  
  - `inputs`.  
  - `type`: `"unsigned"`, `"signed"`, or `"float"`.  
  - `value`: comparison threshold.
- **Notes:** No direct `!greater_than` variant exists; use `lower_than`/`equals` to express the complementary logic.

### `lower_than`
- **Purpose:** Numeric less-than comparison.
- **Arguments:**  
  - `inputs`.  
  - `type`: `"unsigned"`, `"signed"`, or `"float"`.  
  - `value`: comparison threshold.
- **Notes:** No direct `!lower_than` matcher exists; use `greater_than`/`equals` to cover the opposite condition.

### `match_regex`
- **Purpose:** Evaluate a RE2 regular expression.
- **Arguments:**  
  - `inputs`.  
  - `regex`: pattern string.  
  - `options` (optional map):  
    - `min_length` (non-negative integer).  
    - `case_sensitive` (boolean, defaults to `false`).
- **Notes:** Negation `!match_regex` is available.

### `match_regex_with_checksum`
- **Purpose:** Run a regular expression alongside a checksum gate.
- **Arguments:**  
  - `inputs`.  
  - `regex`: pattern string.  
  - `checksum`: expected checksum identifier; compiled via `checksum_builder`.  
  - `options` (optional): `min_length`, `case_sensitive`.
- **Notes:** Negated form `!match_regex_with_checksum` is supported. Useful for large pattern sets where checksum pre-filtering trims evaluation cost.

### `phrase_match`
- **Purpose:** Fast multi-string search using the Aho–Corasick algorithm.
- **Arguments:**  
  - `inputs`.  
  - `list`: array of phrases.  
  - `options.enforce_word_boundary` (optional boolean) to require matches on word boundaries.
- **Notes:** Negation `!phrase_match` is supported.

### `ip_match`
- **Purpose:** Match values against IP addresses or CIDR ranges.
- **Arguments:**  
  - `inputs`.  
  - Either `list` (array of IP/CIDR strings) or `data` (rules-data identifier).  
  - Optional transformers may normalise header values before matching.
- **Notes:** Negated form `!ip_match` is supported. Lists are parsed into a radix tree internally.

### `is_xss`
- **Purpose:** Detect cross-site scripting payloads using libinjection.
- **Arguments:** `inputs`.
- **Notes:** Only the positive matcher is available; there is no `!is_xss`.

### `is_sqli`
- **Purpose:** Detect SQL injection payloads using libinjection.
- **Arguments:** `inputs`.
- **Notes:** Only the positive matcher is available; there is no `!is_sqli`.

### `hidden_ascii_match`
- **Purpose:** Flag strings containing hidden or non-printable ASCII characters.
- **Arguments:** `inputs`.
- **Notes:** Only the positive matcher is available; there is no `!hidden_ascii_match`.

### `exists` / `!exists`
- **Purpose:** Assert the presence (`exists`) or absence (`!exists`) of addresses.
- **Arguments:**  
  - `exists`: `inputs` (variadic). Returns `true` as soon as any address resolves; key paths are traversed so nested lookups honour the provided selectors.  
  - `!exists`: `inputs` (exactly one). Returns `true` only when the address cannot be resolved.
- **Notes:** Implemented as scalar conditions; the negated form must target a single address.

---

## Detector operators

Detector operators combine multiple signals and heuristics. They are versioned: a rule can request a specific revision using the `operator@vN` syntax, but the engine enforces the maximum version compiled into libddwaf (see the `version` constant in each detector).

### `lfi_detector` (≤ v2)
- **Purpose:** Detect local file inclusion attempts.
- **Arguments:**  
  - `resource`: unary argument pointing to the resolved filesystem path (for example, the file ultimately accessed).  
  - `params`: variadic argument listing user-controlled inputs that contributed to the path.
- **Behaviour:** Validates that user input is not escaping directories or forging absolute paths. Handles Unix and Windows path semantics.

### `ssrf_detector` (≤ v3)
- **Purpose:** Detect server-side request forgery attempts.
- **Arguments:**  
  - `resource`: the outbound URL being fetched.  
  - `params`: request parameters associated with that URL.  
  - `options` (optional map):  
    - `authority-inspection` (bool, default `true`).  
    - `path-inspection` (bool, default `false`).  
    - `query-inspection` (bool, default `false`).  
    - `forbid-full-url-injection` (bool, default `false`).  
    - `enforce-policy-without-injection` (bool, default `false`).  
  - `policy` (optional map):  
    - `allowed-schemes` (array of scheme strings; defaults to `["https","http","ftps","ftp"]`).  
    - `forbidden-domains` (array; defaults provided in the header).  
    - `forbidden-ips` (array; defaults include RFC1918, loopback, and cloud metadata ranges).
- **Behaviour:** Normalises the destination URL, evaluates it against the policy (schemes, domains, IPs), and inspects user parameters for full-URL injections.

### `sqli_detector` (≤ v3)
- **Purpose:** Detect SQL injection by analysing the concrete query and bound parameters.
- **Arguments:**  
  - `resource`: SQL statement emitted by the application.  
  - `params`: parameters interpolated into the statement.  
  - `db_type`: string identifying the SQL dialect (`mysql`, `pgsql`, `sqlite`, etc.).
- **Behaviour:** Tokenises the query, strips literals, and inspects parameter tokens for tautologies, comment abuse, or structural anomalies given the specified dialect.

### `shi_detector` (≤ v1)
- **Purpose:** Detect shell injection across command invocations.
- **Arguments:**  
  - `resource`: shell command (string or array of tokens).  
  - `params`: user-controlled arguments being appended to the command.
- **Behaviour:** Tokenises both the base command and parameters, looking for injected commands or dangerous expansions (for example, `;`, `&&`, subshell operators). Supports string or array representations of the command.

### `cmdi_detector` (≤ v1)
- **Purpose:** Detect command injection patterns in command-line executions.
- **Arguments:**  
  - `resource`: executable path or command string captured from the application.  
  - `params`: user-provided arguments.
- **Behaviour:** Identifies attempt to append shell directives or bypass argument escaping by understanding known shell option formats (for Bash, PowerShell, etc.) and highlighting injected payloads.

---

## Operator negation

Only the scalar match operators `equals`, `exact_match`, `match_regex`, `match_regex_with_checksum`, `phrase_match`, and `ip_match` expose a dedicated negated variant prefixed with `!`—for example, `!match_regex` or `!ip_match`. Those negated operators accept exactly one address and invert the underlying predicate. Detector operators (`*_detector`) and the remaining scalar matchers do **not** provide negated forms; use complementary positive operators if alternative behaviour is needed.

When combining operators, remember that each address may declare transformers and that the global condition applies them in the order specified in the rule definition.
