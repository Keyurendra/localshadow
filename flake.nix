{
  description = "AccuKnox OmniScan";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            config.allowUnfreePredicate = p: builtins.elem (pkgs.lib.getName p) [
              "terraform"
            ];
          };
          entrypointOpenshiftVirtualization = import ./docker/entrypoint-openshift-virtualization.nix { inherit pkgs; };
          entrypointKubernetesNodeScan = import ./docker/entrypoint-kubernetes-node-scan.nix { inherit pkgs; };
        in
        {
          formatter = pkgs.nixpkgs-fmt;
          packages = rec {
            omni = pkgs.buildGoModule {
              pname = "omni";
              version = "0.0.0";
              src = ./.;
              vendorHash = "sha256-1I7P5b52iwhNUMzbZ5qSA5OQQ9JmbZZz/psavtuN2IA=";
              ldflags = [ "-s" "-w" ];
              env = {
                CGO_ENABLED = 0;
                GOEXPERIMENT = "jsonv2";
                GOPRIVATE = "github.com/accuknox/*";
                HOME = "/tmp"; # set HOME so go binary finds .netrc
              };
              subPackages = [ "cmd/omni" ];
              nativeBuildInputs = [ pkgs.installShellFiles ];
              postInstall = ''
                for shell in bash zsh; do
                  installShellCompletion --$shell ./completion/$shell/omni
                done
              '';
            };
            dockerImageOmni = pkgs.dockerTools.buildImage {
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
                  pkgs.dockerTools.caCertificates
                  pkgs.mount
                  pkgs.ntfs3g
                  pkgs.trivy
                  pkgs.clamav
                  omni
                  entrypointOpenshiftVirtualization
                  entrypointKubernetesNodeScan
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
            dockerImageOmniOperator = pkgs.dockerTools.buildImage {
              name = "public.ecr.aws/k9v9d5v2/omni-operator";
              tag = "latest";
              copyToRoot = pkgs.buildEnv {
                name = "rootfs";
                paths = [ omni ];
                pathsToLink = [ "/bin" ];
              };
              config = {
                Entrypoint = [ "/bin/omni" ];
                User = "65532:65532";
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
              golangci-lint
              operator-sdk
            ];
          };
        });
}
