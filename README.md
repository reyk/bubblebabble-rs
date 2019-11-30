# Bubble Babble Binary Data Encoding

[![docs.rs](https://docs.rs/bubblebabble/badge.svg)](https://docs.rs/bubblebabble)
[![Crates.IO](https://img.shields.io/crates/v/bubblebabble.svg)](https://crates.io/crates/bubblebabble)
[![Build Status](https://travis-ci.org/reyk/bubblebabble-rs.svg?branch=master)](https://travis-ci.org/reyk/bubblebabble-rs)
[![License](https://img.shields.io/badge/license-BSD-blue.svg)](https://raw.githubusercontent.com/reyk/bubblebabble-rs/master/LICENSE)

Convert `bytes` to the "Bubble Babble" data encoding that was defined
as a mechanism to encode SSH public key fingerprints in a
human-readable format.

# Examples

```rust
use bubblebabble::*;
use std::net::Ipv6Addr;

// Convert 128-bit binary to bubblebabble
let data = [
    0x2a, 0x0a, 0xe5, 0xc0, 0, 0x2, 0, 0x5, 0x5c, 0xf9, 0xcc, 0xc8, 0x7c, 0x48, 0x97, 0xc0,
];
let babble = bubblebabble(&data);
assert_eq!(babble, "xepib-panus-bubub-dubyb-hilyz-nefas-myzug-mihos-bexux");

// Convert IPv6 address to stablebabble
let localhost: Ipv6Addr = "::1".parse().unwrap();
let babbleaddr = stablebabble(&localhost.octets());
assert_eq!(babbleaddr, "xebab-7wa-caxax");
```

## See Also

[The Bubble Babble Binary Data Encoding, Antti Huima, 2011](http://web.mit.edu/kenta/www/one/bubblebabble/spec/jrtrjwzi/draft-huima-01.txt)

## Copyright and license

Licensed under a BSD-style license, see [LICENSE] for details.

[LICENSE]: LICENSE
