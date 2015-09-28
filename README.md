# Minimal package for ed25519 signatures

[![Build Status](https://travis-ci.org/thoughtpolice/hs-ed25519.png?branch=master)](https://travis-ci.org/thoughtpolice/hs-ed25519)
[![MIT](http://b.repl.ca/v1/license-MIT-blue.png)](http://en.wikipedia.org/wiki/MIT_License)
[![Haskell](http://b.repl.ca/v1/language-haskell-lightgrey.png)](http://www.haskell.org)

This package implements minimal bindings to the [ed25519][] signature
scheme. It's designed to be small, with no dependencies, and fast. It
also comes with extensive guidelines and detailed documentation. It
should be relatively easy to both depend on directly with Cabal or
even copy into any projects that need it directly.

For full details (including notes on the underlying implementation),
check out [the docs][].

[ed25519]: http://ed25519.cr.yp.to/
[SUPERCOP]: http://bench.cr.yp.to/supercop.html
[the docs]: http://hackage.haskell.org/package/ed25519/docs/Crypto-Sign-Ed25519.html

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
[issue tracker]: http://github.com/thoughtpolice/hs-ed25519/issues
[gh]: http://github.com/thoughtpolice/hs-ed25519
[bb]: http://bitbucket.org/thoughtpolice/hs-ed25519
[Hackage]: http://hackage.haskell.org/package/ed25519
