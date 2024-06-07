// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "sha256.hpp"
#include "test.hpp"

#include <utility>
#include <vector>

TEST(TestSha256, RandomInputTest)
{
    std::vector<std::pair<std::string, std::string>> samples{
        {"YqJwhSIzGlqqehMom6Z3Ok4bqLFN2Kpn",
            "403b62faf37de5e5e6e02a300a2ed1a42e2dbf9d83951ec8b288bf026b6f79a2"},
        {"3f3qLGvqHleNTAWS7MxB0QGXLoS1IMk1",
            "535a34d235d1a0914d49abd6d9e6ceb8cd55ce4948214e7805e5d829616c1a3b"},
        {"QZly1PUSiJ5sxknDjzh5ZKOmam9gGSnl",
            "2af42b61fc7b75cbfcc2fb7aaee9ba287e0fcdcae284f8498cdcf97bdfa8ad6c"},
        {"np1WXOU7JTH1zd3N3eEEVpojfCSG07qN",
            "3fadb64fe82e69e500aeba66aaa4042dcf1e33f7636b3f826bb13651de8c3c6e"},
        {"kZCS8KnHLcBGyJvqXKVMTYZyQvKdXONI",
            "34990ff286e09cb6c88ca4db69143de0ef495820ecbc1b874e1171ce3038015c"},
        {"zmZO2KUR3KKa2llyA8vdQuLSjEIHRGDx",
            "4ce5dcf2b57e70660cae49d5e9747f0b6e6f3d0a43173858ced3543735474a37"},
        {"xcd5YpxGerWhw6B0lR4G7duiMftNSu8V",
            "06784e3810f127b2e1cb1c37b184ed7723a19cd4ba5f3afc01730646b20db89a"},
        {"PAIbUxTu9WiHNUXxlzwrb6E4oEkJqwM8",
            "87a5aefe7cc55c91f556d2e37b0c3871b0792db570ec57abe6b07a0d96b9ca94"},
        {"tFUFGUSS6GXa6IQwTXHULFPt4GeeaKnR",
            "505349119e977eefdd0cb24715a9133e0c4b93597cb4e94f953f3b4eadd63725"},
        {"WfUaDo5mEMZIH15gfIxBh3mwfJDGNL6h",
            "dce8225f0559d76a1928c004a6a55887293761c40623cdbbe7d31c97326d8c8b"},
        {"auTy0yqqU9QvVGjhCGCx2C7Zx5wCE61P",
            "5af6e6fbaf3a551abb60c0a366668581a42584dd1c3ae5756d25172e6f0a8554"},
        {"ue30YmBaXqXejTRwWHOPABDVo0NCOydy",
            "0002bef6617f034614d9444f6a74b86136037534a162837639d8c4d8d81844ac"},
        {"m7UkVhIDVOtqXaVvkFbGoc6WUwG4s8D6",
            "4e9d3107abf6d9128de5a12d9ce2bbd5c61a12e993c01832ce531f728ee5c21a"},
        {"PqT7NuFLaTlHQulpoccYzAgvDRJHbp3M",
            "37187a7c80428feb5c0976b3f32d44616a52799ebfc7f31f95613f4e5d938678"},
        {"RgbxLhrZFbrYv5XykdSBlU537fDYkW1g",
            "34144fc83c319f8ceff879d67531d7b9aed67bc81a2ec02f9ad401b52fe217b6"},
        {"wngyajXn1cSOaczvTomAAItUXwGZOEoz",
            "4a1e660e9b4f63fa28d489f025f04deed37045a051b590e8ab36617bcc307e81"},
        {"Esyl9moe4yShgxayVGaGTP4nP0cZCoVC",
            "a4d0f3b09d6ade659061fb1d21a5a5ef07d9b71bdc0ca2f389466d8a4ac53527"},
        {"qkXBYY4xnD1dGLthAYZCo2me3c5MG58q",
            "ab5af4c9a196e775fd25e84e33a118d422d8ed983f6bb4b9e676fc028723648b"},
        {"XPhl2droso1w5qdf9kt7ztzuL0a3T8zi",
            "48f76b330cf0d34a1942956af302f6b85d6806eb52f8a736a057744298be58e2"},
        {"uVF4yUAufiREPkPFwlUOrEsQ10duGD0L",
            "e61c936a0d8c85f4bc9d22e25bca6cea9ac6b2097fd567f60d5efa38c34cfb30"},
        {"JaoF4myRTg4TCMm", "a1f9adb16b52ef2c845e85bc552a86c6426cb2780bb061e34c8982e41c2e36af"},
        {"1sj5xeZxRF623qV", "97cc8c0f72ed810be1f3d9653372926e6e5884f341e58f4edfb2f875b097655e"},
        {"ipsEfuH3nmPqzcp", "32adf694cb470c2ffd50b26fb684510510b0d4b227f89bd2ae5ba49d2a6e4c3a"},
        {"Biy1I5idi5TQK9e", "76d42814fecde876121bbf8c73721893578077092eb30aa072a78679f80a48a8"},
        {"dE8BpndRLevSL81", "6d7218b399480aed8afb21194f57daf1767c4ac20ff5edcd2c757e7c214d9ef7"},
        {"92eB4V0FBDivRwB", "ff7e8ec21651f29cfeb692318b506db7b09be207765ff4eae000a8a2f9b579cc"},
        {"we37ZqY2Swj5hrf", "da1134a980af5aa6a74d2cd09f6478ada8cfd69e4385a66bf8393345629db865"},
        {"YmmkJi9JmR5F4uK", "6eb6206a23058f0c8c945b79dab52e374a7cccfde17928312d7dd1156ec0b013"},
        {"xVdC0kucB0ykKd3", "065093b4389e81c2235ccf57c4f7d9916e478ece5209aac5d850ae82d7c1106b"},
        {"kovdtReY2LmgFn8", "d51e607c19b019efe4d3768bb9e0202c0b439c0c556bd4ba87e2e05417f54c3f"},
    };

    for (auto &[original, hash] : samples) {
        ddwaf::sha256_hash hasher;
        hasher << original;

        EXPECT_STR(hasher.digest(), hash.c_str());
    }
}
