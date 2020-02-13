![Cabal Build](https://github.com/larskuhtz/hostaddress/workflows/Cabal%20Build/badge.svg)

# Haskell Tools for Host Addresses

This package implements Host addresses as described in RFC2396 section 3.2.2
with additional consideration of

* RFC1123 (additional restrictions for hostnames),
* RFC1034 (disambiguate domain names and IPv4 addresses),
* RFC4291 (parsing of IPv6 addresses), and
* RFC3986 and RFC5952 (IPv6 literals within host addresses).

# Build from Source

```sh
cabal v2-build
```

The following optional build flags are available:

*   `-fwith-aeson`: build `ToJSON` and `FromJSON` instance for use with
    [aeson](https://hackage.haskell.org/package/aeson).

*   `-fwith-configuration-tools`: build instances and functions for supporting
    the use with
    [configuration-tools](https://hackage.haskell.org/package/configuration-tools).

*   `-fwith-quickcheck`: include function for generating arbitrary values and
    `Arbitrary` instance for use with
    [QuickCheck](https://hackage.haskell.org/package/QuickCheck).

# Documentation

Documentation is available at [https://hackage.haskell.org/package/hostaddress/]().
