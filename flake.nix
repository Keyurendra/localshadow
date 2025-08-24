{
  description = "AccuKnox OmniScan";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfreePredicate = p: builtins.elem (pkgs.lib.getName p) [
            "terraform"
          ];
        };
      in
      {
        formatter = pkgs.nixpkgs-fmt;
        packages.default = pkgs.buildGoModule {
          pname = "omni";
          version = "0.0.0";
          src = ./.;
          vendorHash = "sha256-D6EqjnUFxookTLss4Xcva/jHilvtWMbIJajAQA4qaec=";
          env.CGO_ENABLED = 0;
          subPackages = [ "cmd/omni" ];
          nativeBuildInputs = [ pkgs.installShellFiles ];
          postInstall = ''
            for shell in bash zsh; do
              installShellCompletion --$shell ./completion/$shell/omni
            done
          '';
        };
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            nixd
            nixpkgs-fmt
            go
            go-tools
            gopls
            awscli2
            google-cloud-sdk
            azure-cli
            terraform-ls
            terraform
          ];
        };
      });
}
