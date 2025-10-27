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
        entrypoint = import ./docker/entrypoint.nix { inherit pkgs; };
      in
      {
        formatter = pkgs.nixpkgs-fmt;
        packages = rec {
          omni = pkgs.buildGoModule {
            pname = "omni";
            version = "0.0.0";
            src = ./.;
            vendorHash = "sha256-8PDYulmj8Cfwo19rEE0XfWLjVjoQRsNyr3p61QsFAKw=";
            env = {
              CGO_ENABLED = 0;
              GOEXPERIMENT = "jsonv2";
            };
            subPackages = [ "cmd/omni" ];
            nativeBuildInputs = [ pkgs.installShellFiles ];
            postInstall = ''
              for shell in bash zsh; do
                installShellCompletion --$shell ./completion/$shell/omni
              done
            '';
          };
          dockerImage = pkgs.dockerTools.buildImage {
            name = "public.ecr.aws/k9v9d5v2/omni";
            tag = "latest";
            runAsRoot = ''
              #!${pkgs.runtimeShell}
              ${pkgs.dockerTools.shadowSetup}
              groupadd -r clamav
              useradd -r -g clamav clamav
              install -d -o clamav -g clamav /var/lib/clamav
            '';
            copyToRoot = pkgs.buildEnv {
              name = "rootfs";
              paths = [
                pkgs.dockerTools.binSh
                pkgs.coreutils
                pkgs.dockerTools.caCertificates
                pkgs.mount
                pkgs.ntfs3g
                pkgs.trivy
                pkgs.clamav
                omni
                entrypoint
                (pkgs.runCommand "freshclam-conf" { } ''
                  mkdir -p $out/etc/clamav
                  cp ${./docker/freshclam.conf} $out/etc/clamav/freshclam.conf
                '')
              ];
              pathsToLink = [ "/bin" "/etc" ];
            };
            config = {
              Cmd = [ "${omni}/bin/omni" ];
            };
          };
          default = omni;
        };
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            nixd
            nixpkgs-fmt
            go
            go-tools
            gotools
            gofumpt
            gopls
            terraform-ls
            terraform
            kubebuilder
            kubevirt
            kubernetes-code-generator
            goreleaser
          ];
        };
      });
}
