/*
 * Copyright (c) 2019 Reyk Floeter. All rights reserved.
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2008 Alexander von Gernler.  All rights reserved.
 * Copyright (c) 2010,2011 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

use std::net::Ipv6Addr;

//! Bubble Babble Binary Data Encoding
//!
//! Convert `bytes` to the "Bubble Babble" data encoding that was defined
//! as a mechanism to encoding SSH public key fingerprints in a human-readable
//! format.
//!
//! # See Also
//!
//! [The Bubble Babble Binary Data Encoding, Antti Huima, 2011](http://web.mit.edu/kenta/www/one/bubblebabble/spec/jrtrjwzi/draft-huima-01.txt)

/// Convert bytes to Bubble Babble `String`.
///
/// This is the standard and human-readable format.  The Bubble Babble
/// includes a checksum that is carried through each generated word.
pub fn bubblebabble(bytes: &[u8]) -> String {
    bubblebabble_impl(bytes, true)
}

/// Convert bytes to stable Babble `String`.
///
/// This modified format lacks the checksum but keeps every word
/// stable as they don't include the state.  It also compresses repeated
/// words by printing them with a prepended counter.
pub fn stablebabble(bytes: &[u8]) -> String {
    bubblebabble_impl(bytes, false)
}

fn bubblebabble_impl(bytes: &[u8], use_seed: bool) -> String {
    let vowels = ['a', 'e', 'i', 'o', 'u', 'y'];
    let consonants = [
        'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm', 'n', 'p', 'r', 's', 't', 'v', 'z', 'x',
    ];
    let rounds = (bytes.len() / 2) + 1;
    let mut bubble = String::with_capacity(rounds * 6);
    let mut seed = 1;

    bubble.push('x');

    // taken from OpenSSH ssh/sshkey.c
    for i in 0..rounds {
        let mut idx = [0usize; 5];

        if (i + 1 < rounds) || bytes.len() % 2 != 0 {
            idx[0] = ((((bytes[2 * i]) as usize >> 6) & 3) + seed) % 6;
            idx[1] = ((bytes[2 * i]) >> 2) as usize & 15;
            idx[2] = (((bytes[2 * i]) & 3) as usize + (seed / 6)) % 6;

            bubble.push(vowels[idx[0]]);
            bubble.push(consonants[idx[1]]);
            bubble.push(vowels[idx[2]]);

            if (i + 1) < rounds {
                idx[3] = ((bytes[(2 * i) + 1]) as usize >> 4) & 15;
                idx[4] = ((bytes[(2 * i) + 1]) as usize) & 15;

                bubble.push(consonants[idx[3]]);
                bubble.push('-');
                bubble.push(consonants[idx[4]]);

                seed = if use_seed {
                    // The seed changes each word and serves as kind of a checksum
                    ((seed * 5)
                        + (((bytes[2 * i]) as usize * 7) as usize
                            + ((bytes[(2 * i) as usize + 1]) as usize)))
                        % 36
                } else {
                    0
                };
            }
        } else {
            idx[0] = seed % 6;
            idx[1] = 16;
            idx[2] = seed / 6;

            bubble.push(vowels[idx[0]]);
            bubble.push(consonants[idx[1]]);
            bubble.push(vowels[idx[2]]);
        }
    }

    bubble.push('x');

    if use_seed {
        return bubble;
    }

    // Find and replace repetitioins
    let mut result = String::new();
    let mut last = "";
    let mut count = 1;
    for (i, word) in bubble.split('-').enumerate() {
        if last == word {
            count += 1;
        } else if i > 0 {
            if i > 1 {
                result.push('-');
            }
            if count > 1 {
                result.push_str(&count.to_string());
            }
            result.push_str(last);
            count = 1;
        }
        last = word;
    }
    result.push('-');
    result.push_str(last);

    // Use "wa" to represent a 0
    result.replace("babab", "wa")
}

fn main() {
    let tests = [
        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2),
        "2a0a:e5c0:2:5:5cf9:ccc8:7c48:97c0".parse().unwrap(),
        "fe80::4685:ff:fe76:1722".parse().unwrap(),
    ];

    for addr in tests.iter() {
        eprintln!("{} => {}", addr, stablebabble(&addr.octets()));
    }
}
