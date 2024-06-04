{ nixpkgs ? import <nixpkgs> {} }:

nixpkgs.mkShell {
  buildInputs = [
    nixpkgs.bpftools
    nixpkgs.llvmPackages.bintools
  ];

  # LIBCLANG_PATH = "${nixpkgs.libclang.lib}/lib";
  # LIBVNCSERVER_HEADER_FILE = "${nixpkgs.libvncserver.dev}/include/rfb/rfb.h";
}
