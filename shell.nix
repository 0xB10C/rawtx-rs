{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  hardeningDisable = [ "stackprotector" "fortify" ];
    nativeBuildInputs = [
      pkgs.clippy
      pkgs.cargo
      pkgs.rustfmt
      pkgs.rustc
      pkgs.clang_15
    ];
}
