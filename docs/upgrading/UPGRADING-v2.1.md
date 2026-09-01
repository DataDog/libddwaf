# Upgrading libddwaf to v2.1.0

Version 2.1.0 preserves the 16-byte `ddwaf_object` layout and remains binary
compatible with 2.0.x while allowing arrays and maps to grow beyond 65,535
elements. Most consumers require no code changes. Consumers that inspect object
types directly and for which there is a possibility of encountering such large
arrays/maps should handle the new large-container types.

This version represents an API and ABI break if inspecting code encounters such
large arrays or maps. This might be possible if bindings relied on current
error behavior when exceeding the previous 16-bit capacity of maps or arrays
or, more indirectly, if, in the future, remote config provides large maps and
arrays, e.g. for large lists of blocked IP addresses.

## Recompile to use wider container capacities

The source signatures of `ddwaf_object_set_array` and
`ddwaf_object_set_map` now accept a `size_t` capacity. Continue calling these
functions by their existing names:

```c
ddwaf_object array;
ddwaf_object_set_array(&array, capacity, alloc);

ddwaf_object map;
ddwaf_object_set_map(&map, capacity, alloc);
```

The v2.1 header maps those names to transitional ABI symbols with the wider
signature. Do not call `ddwaf_object_set_array_large` or
`ddwaf_object_set_map_large` directly; those symbol names will be removed in
version 3.

Existing binaries remain compatible and continue using the v2.0 symbols with
16-bit capacities. Recompile against the v2.1 header to request an initial
capacity above 65,535.

Compact containers are automatically promoted when an insertion grows them
beyond 65,535 elements. Large arrays and maps have 28-bit size and capacity
fields. Capacity is limited to the smaller of 268,435,455 and the number of
elements addressable by `SIZE_MAX`; an oversized creation or exhausted growth
returns failure without modifying the existing object.

## Handle the new object types

The public type enum now includes `DDWAF_OBJ_LARGE_ARRAY` and
`DDWAF_OBJ_LARGE_MAP`. Use `ddwaf_object_is_array` and `ddwaf_object_is_map`
when branching on the container category; both predicates recognize compact
and large containers:

```c
if (ddwaf_object_is_array(&object)) {
    /* Handle an array. */
} else if (ddwaf_object_is_map(&object)) {
    /* Handle a map. */
}
```

The other public accessor functions also require no special handling:
`ddwaf_object_get_size`, `ddwaf_object_at_key`, and `ddwaf_object_at_value`
work with compact and large containers.

Code that already switches on `ddwaf_object_get_type()` or reads the public
`type` field directly should add the corresponding large-container cases:

```c
switch (ddwaf_object_get_type(&object)) {
case DDWAF_OBJ_ARRAY:
case DDWAF_OBJ_LARGE_ARRAY:
    /* Handle an array. */
    break;
case DDWAF_OBJ_MAP:
case DDWAF_OBJ_LARGE_MAP:
    /* Handle a map. */
    break;
default:
    /* Handle scalar and invalid types. */
    break;
}
```

Prefer the accessor functions over reading `via.array` or `via.map` directly,
because large containers use different union members.
