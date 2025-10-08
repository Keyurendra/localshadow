{
  description = "AccuKnox OmniScan";
  inputs = {
    unstable.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { unstable, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import unstable {
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
            vendorHash = "sha256-XrQsn/mecYsWvdStbywOCnVAuo8asJOl80UBPpgWHlk=";
            env.CGO_ENABLED = 0;
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
          packages = [
            pkgs.nixd
            pkgs.nixpkgs-fmt
            pkgs.go
            pkgs.go-tools
            pkgs.gotools
            pkgs.gofumpt
            pkgs.gopls
            pkgs.awscli2
            pkgs.google-cloud-sdk
            pkgs.azure-cli
            pkgs.terraform-ls
            pkgs.terraform
            pkgs.kubebuilder
            pkgs.kubevirt
            pkgs.kubernetes-code-generator
          ];
        };
      });
}
