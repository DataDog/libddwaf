// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <algorithm>
#include <cstddef>

#include "cow_string.hpp"
#include "transformer/normalize_path.hpp"

namespace ddwaf::transformer {

bool normalize_path::transform_impl(cow_string &str)
{
    bool modified = false;
    std::size_t read = 0;
    std::size_t write = 0;

    // Our algorithm is quite simple: we look for `./`. If we find that, we check if the
    // preceeding char is:
    //  - `/` (and thus skip the `./`)
    //  - `/.` and we thus erase the last directory
    while (read < str.length()) {
        // Everything is cool, writing away
        if (str.at(read) != '.' || (read + 1 != str.length() && str.at(read + 1) != '/')) {
            if (str.copy_char(read++, write++)) {
                modified = true;
            }
            continue;
        }

        // We handle both the `./script` and `bla/./bla` here by ignoring the next two
        // characters
        if (read == 0 || str.at(read - 1) == '/') {
            read += 2;
        }

        // We handle /../ by moving the write head back to the previous `/`
        else if (read > 1 && str.at(read - 1) == '.' && str.at(read - 2) == '/') {
            // The write head already wrote /., we need to move it back by three
            //  MIN make sure we can't underflow although I don't really see how that could
            //  happen
            write -= std::min(write, static_cast<std::size_t>(3));

            while (write != 0 && str[write] != '/') { write -= 1; }

            // Move forward the read head, and add back the / to the write head
            str[write++] = '/';
            read += 2;
            modified = true;
        }

        // nvm, false alarm, just a dir ending with .
        else {
            if (str.copy_char(read++, write++)) {
                modified = true;
            }
        }
    }

    if (!modified) {
        return false;
    }

    str.truncate(write);

    return true;
}

bool normalize_path_win::transform_impl(cow_string &str)
{
    bool normalized = false;
    // That's quite a blunt conversion but that's what ModSecurity is doing so ¯\_(ツ)_/¯
    //  https://github.com/SpiderLabs/ModSecurity/blob/b66224853b4e9d30e0a44d16b29d5ed3842a6b11/src/actions/transformations/normalise_path.cc#L64
    for (std::size_t pos = 0; pos < str.length(); ++pos) {
        if (str.at(pos) == '\\') {
            normalized = true;
            str[pos] = '/';
        }
    }
    auto res = normalize_path::transform_impl(str);
    return res || normalized;
}

} // namespace ddwaf::transformer
