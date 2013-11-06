# Minimal package for ed25519 signatures

[![Build Status](https://travis-ci.org/thoughtpolice/hs-ed25519.png?branch=master)](https://travis-ci.org/thoughtpolice/hs-ed25519)

This package implements minimal bindings to the [ed25519][] signature
scheme. It should be relatively easy to both depend on, or include
outright in your executable/package itself.

The underlying implementation is the `ref10` code from [SUPERCOP][],
which was originally implemented by Dan J. Bernstein.

[ed25519]: http://ed25519.cr.yp.to/
[SUPERCOP]: http://bench.cr.yp.to/supercop.html

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
