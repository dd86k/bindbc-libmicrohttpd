# bindbc-libmicrohttpd

Unofficial BindBC dynamic and static bindings for libmicrohttpd, a small HTTP
daemon library.

On Windows, you'll need the
[libmicrohttpd-latest-w32-bin.zip](https://www.gnu.org/software/libmicrohttpd/)
archive.

On Ubuntu, you'll need the `libmicrohttpd12` (or `libmicrohttpd12t64`) package for
the shared library. Otherwise, for the static configuration, the `libmicrohttpd-dev`
package (for `libmicrohttpd.a`).

The example supports both dynamic and static configuration.

To run the example, execute `dub :example` (dmd will have issues with BetterC).

Notes:
- Static config makes the dynamic dependencies more explicit.
- `dub :example -c static --compiler=ldc2` for static example.

# Configuration

## Static

To get the static configuration, set `BindBC_LibMicroHTTPD_Static` version.

It also respects the `BindBC_Static` version.

## Versioning

Currently, the supported versions are listed below.

| Version | Found in | Configuration |
|---|---|---|
| 0.9.59 | Ubuntu 18.04 | Baseline, no versions defined |
| 0.9.66 | Ubuntu 20.04 | `LibMicroHTTPD_v000966` |
| 0.9.75 | Ubuntu 22.04 | `LibMicroHTTPD_v000975` |

Defined versions also effect static configurations.

I currently don't have a list of functions with their corresponding versions
so the versions are rough, but I don't think I'd mind supporting more versions.

The `MHD_VERSION` constant is defined depending on the version configured.

# License

While this package is using the Boost license (BSL-1.0), the libmicrohttpd library is
licensed LGPL 2.1.

libmicrohttpd Copyright:
```text
     Copyright (C) 2006-2021 Christian Grothoff (and other contributing authors)
     Copyright (C) 2014-2022 Evgeny Grin (Karlson2k)
```