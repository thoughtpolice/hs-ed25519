# Minimal package for ed25519 signatures


[![Linux Build Status](https://img.shields.io/travis/thoughtpolice/hs-ed25519/master.svg?label=Linux%20build)](https://travis-ci.org/thoughtpolice/hs-ed25519)
[![Windows Build Status](https://img.shields.io/appveyor/ci/thoughtpolice/hs-ed25519/master.svg?label=Windows%20build)](https://ci.appveyor.com/project/thoughtpolice/hs-ed25519/branch/master)
[![Hackage version](https://img.shields.io/hackage/v/ed25519.svg?label=Hackage)](https://hackage.haskell.org/package/ed25519)
[![Stackage version](https://www.stackage.org/package/ed25519/badge/lts?label=Stackage)](https://www.stackage.org/package/ed25519)
[![MIT](https://img.shields.io/badge/License-MIT-blue.png)](https://en.wikipedia.org/wiki/MIT_License)
[![Haskell](https://img.shields.io/badge/Language-Haskell-yellowgreen.svg)](https://www.haskell.org)

This package implements minimal bindings to the [ed25519][] signature
scheme. It's designed to be small, with no dependencies, and fast. It
also comes with extensive guidelines and detailed documentation. It
should be relatively easy to both depend on directly with Cabal or
even copy into any projects that need it directly.

For full details (including notes on the underlying implementation),
check out [the docs][].

[ed25519]: https://ed25519.cr.yp.to/
[SUPERCOP]: https://bench.cr.yp.to/supercop.html
[the docs]: https://hackage.haskell.org/package/ed25519/docs/Crypto-Sign-Ed25519.html

# Installation

It's just a `cabal install` away on [Hackage][]:

```bash
$ cabal install ed25519
```

# Join in

Be sure to read the [contributing guidelines][contribute]. File bugs
in the GitHub [issue tracker][].

Master [git repository][gh]:

* `git clone https://github.com/thoughtpolice/hs-ed25519.git`

There's also a [BitBucket mirror][bb]:

* `git clone https://bitbucket.org/thoughtpolice/hs-ed25519.git`

# Authors

See [AUTHORS.txt](https://raw.github.com/thoughtpolice/hs-ed25519/master/AUTHORS.txt).

# License

MIT. See
[LICENSE.txt](https://raw.github.com/thoughtpolice/hs-ed25519/master/LICENSE.txt)
for terms of copyright and redistribution.

[contribute]: https://github.com/thoughtpolice/hs-ed25519/blob/master/CONTRIBUTING.md
[issue tracker]: https://github.com/thoughtpolice/hs-ed25519/issues
[gh]: https://github.com/thoughtpolice/hs-ed25519
[bb]: https://bitbucket.org/thoughtpolice/hs-ed25519
[Hackage]: https://hackage.haskell.org/package/ed25519
