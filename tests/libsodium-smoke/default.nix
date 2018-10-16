with import <nixpkgs> {};

stdenv.mkDerivation rec {
  name = "hs-ed25519-sodium-smoke";
  src = ./.;

  buildInputs = [ libsodium ];

  installPhase = ''
    touch bins.h
    for x in blob blob.sig foo.pk foo.sk; do
      ${vim}/bin/xxd -i $x >> bins.h;
    done

    cat bins.h
    cc -fsanitize=address -std=c11 -o $out smoke.c -lsodium
  '';
}
