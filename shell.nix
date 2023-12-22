{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  hardeningDisable = [ "stackprotector" "fortify" ];
    nativeBuildInputs = [
      pkgs.cargo
      pkgs.rustfmt
      pkgs.rustc
      pkgs.clang_15
    ];
}
