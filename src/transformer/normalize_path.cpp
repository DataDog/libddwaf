// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <transformer/normalize_path.hpp>

namespace ddwaf::transformer {

bool normalize_path::transform(lazy_string &str)
{
    uint64_t read = 0;
    uint64_t write = 0;

    // Our algorithm is quite simple: we look for `./`. If we find that, we check if the
    // preceeding char is:
    //  - `/` (and thus skip the `./`)
    //  - `/.` and we thus erase the last directory
    while (read < str.length()) {
        // Everything is cool, writing away
        if (str.at(read) != '.' || (read + 1 != str.length() && str.at(read + 1) != '/')) {
            if (read != write) {
                str[write] = str.at(read);
            }
            ++read;
            ++write;
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
            write -= std::min(write, (uint64_t)3);

            while (write != 0 && str[write] != '/') { write -= 1; }

            // Move forward the read head, and add back the / to the write head
            str[write++] = '/';
            read += 2;
        }

        // nvm, false alarm, just a dir ending with .
        else {
            if (read != write) {
                str[write] = str.at(read);
            }
            ++read;
            ++write;
        }
    }

    if (!str.modified()) {
        return false;
    }

    str.finalize(write);

    return true;
}

} // namespace ddwaf::transformer