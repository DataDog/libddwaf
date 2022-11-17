load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

git_repository(
  name = "com_google_cel_cpp",
  remote = "https://github.com/google/cel-cpp.git",
  tag = "v0.8.0",
)

load("@com_google_cel_cpp//bazel:deps.bzl", "cel_cpp_deps")
cel_cpp_deps()

load("@com_google_cel_cpp//bazel:deps_extra.bzl", "cel_cpp_deps_extra")
cel_cpp_deps_extra()
