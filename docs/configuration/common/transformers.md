# Transformer Reference

Transformers preprocess request data before operators or rules consume it. They can be chained within rule conditions and are applied in the order listed.

| Name (v1.12+) | Alias (≤ v1.11) | Purpose | Example | Availability |
| --- | --- | --- | --- | --- |
| `remove_nulls` | `removeNulls` | Strip null bytes. | `bla\0bla → blabla` | ≥ v1.0 |
| `html_entity_decode` | `htmlEntityDecode` | Decode HTML entities (UTF-16 aware). | `&lt;&gt;&amp;&quot;&nbsp; → <>&"\xa0` | ≥ v1.0 |
| `js_decode` | `jsDecode` | Decode JavaScript escapes (UTF-16 aware). | `bla\x20bla → bla bla`<br>`\udbff\udfff → \xF0\x8F\xBF\xBF` | ≥ v1.0 |
| `css_decode` | `cssDecode` | Decode CSS escapes (UTF-16 aware). | `"CSS\%0a tran\sf → CSS transformations` | ≥ v1.0 |
| `base64_encode` | `base64Encode` | Base64 encode. | `bla → Ymxh` | ≥ v1.0 |
| `base64_decode` | `base64Decode` | Decode Base64 (RFC 4648). | `Zm9v → foo`<br>`Zm==============9v → ❌` | ≥ v1.0 |
| `base64DecodeExt` | — | Decode Base64 (RFC 2045). **Deprecated** in v1.12. | `Zm==============9v → foo` | ≥ v1.0 (deprecated v1.12) |
| `url_decode` | `urlDecode` | Decode URL encoding. | `%01hex+encoder%0f → \x01hex encoder\x0f` | ≥ v1.0 |
| `url_decode_iis` | `urlDecodeUni` | Decode URL encoding with IIS extensions. | `%u1234 → \xE1\x88\xB4` | ≥ v1.0 |
| `normalize_path` | `normalizePath` | Collapse relative path segments. | `pony/../bla/ → bla/` | ≥ v1.0 |
| `normalize_path_win` | `normalizePathWin` | Collapse Windows-style relative paths. | `pony\\..\\bla\\ → bla/` | ≥ v1.0 |
| `compress_whitespace` | `compressWhiteSpace` | Replace repeated whitespace with a single space. | `bla  bla → bla bla` | ≥ v1.0 |
| `lowercase` | `lowercase` | Convert to lowercase. | `BlA → bla` | ≥ v1.0 |
| `length` | — | Compute string length. **Deprecated** in v1.12. | `bla → 3` | ≥ v1.0 (deprecated v1.12) |
| `shell_unescape` | `cmdLine` | Remove shell escaping. | `normal \t\v\f\n\r (really) → normal(really)` | ≥ v1.0 |
| `remove_comments` | `removeComments` | Strip C/HTML/SQL/shell comments. | `a/*b*/c<!--d-->e--f → ace` | ≥ v1.0 |
| `numerize` | — | Parse integer strings (INT64_MIN ↔ UINT64_MAX). **Deprecated** in v1.12. | `"-123" → -123`<br>`"1.0" → ❌` | ≥ v1.0 (deprecated v1.12) |
| `url_basename` | `_sqr_basename` | Extract filename from URI. | `/path/index.php?a=b → index.php` | ≥ v1.0 |
| `url_path` | `_sqr_filename` | Extract path from URI. | `/path/index.php?a=b → /path/index.php` | ≥ v1.0 |
| `url_querystring` | `_sqr_querystring` | Extract query string from URI. | `/path/index.php?a=b#d → a=b` | ≥ v1.0 |
| `unicode_normalize` | — | Apply Unicode NFKD normalization to UTF-8 strings. | `a𝑎éßıﬁ2⁵—⅖ → aaessifi25-2/5` | ≥ v1.5 |
| `keys_only` | — | Flatten structured data to a list of keys. | `{ a: b, c: { d: e } } → [a, c, d]` | ≥ v1.1 |

Deprecated transformers remain available for backward compatibility but should be avoided in new rules.
