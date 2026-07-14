# Vendored wayland-scanner

This directory is the crates.io `wayland-scanner` 0.31.10 source under its MIT
license. The workspace patches that release locally because its `quick-xml`
0.39 dependency has known denial-of-service vulnerabilities and no compatible
0.31.x release has updated it.

The local delta is deliberately narrow:

- `quick-xml` is 0.41;
- `ByteRef::xml_content()` is updated to the equivalent 0.41
  `ByteRef::xml10_content()` API.

Remove the root `[patch.crates-io]` entry and this directory when an upstream
`wayland-scanner` release used by the GUI stack carries a fixed `quick-xml`.
