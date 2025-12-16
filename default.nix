with import <nixpkgs> {};
stdenv.mkDerivation {
    name = "c-reference-signer-1.0";
    buildInputs = [ stdenv glibc ];
    src = ./.;

    buildPhase = ''
      make clean libmina_signer.so
      '';
    installPhase = ''
      mkdir -p $out/lib
      mv libmina_signer.so $out/lib
      '';
}
