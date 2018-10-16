
```
$ cd $(git rev-parse --show-toplevel)
$ ./nix-shell --run 'cabal new-repl'
Prelude> :script tests/libsodium-smoke/generate.ghci
Prelude> ^D
$ cd tests/libsodium-smoke/
$ nix build && ./result; echo $?
ok
0
$
```
