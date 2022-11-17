load("@rules_cc//cc:defs.bzl", "cc_library")
load("//main:static.bzl", "cc_static_library")


cc_library(
    name = "cel-cpp-wrapper",
    srcs = ["cel_wrapper.cpp"],
    hdrs = ["cel_wrapper.hpp"],
    deps = [
      "@com_google_cel_cpp//eval/public:activation",
      "@com_google_cel_cpp//eval/public:activation_bind_helper",
      "@com_google_cel_cpp//eval/public:builtin_func_registrar",
      "@com_google_cel_cpp//eval/public/containers:field_access",
      "@com_google_cel_cpp//eval/public:cel_expr_builder_factory",
      "@com_google_cel_cpp//parser"
    ],
)

cc_static_library(
    name = "cel-cpp-wrapper-static",
    dep = ":cel-cpp-wrapper",
)

#cc_binary(
    #name = "rule_runner",
    #srcs = ["main.cpp"],
    #deps = [":cel-cpp-wrapper"],
#)
