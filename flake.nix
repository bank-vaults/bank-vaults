{
  description = "A Vault swiss-army knife";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    devenv.url = "github:cachix/devenv";
  };

  outputs = inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        inputs.devenv.flakeModule
      ];

      systems = [ "x86_64-linux" "x86_64-darwin" "aarch64-darwin" ];

      perSystem = { config, self', inputs', pkgs, system, ... }: rec {
        devenv.shells = {
          default = {
            languages = {
              go.enable = true;
              go.package = pkgs.go_1_24;
            };

            services = {
              vault = {
                enable = true;
                package = self'.packages.vault;
              };
            };

            pre-commit.hooks = {
              nixpkgs-fmt.enable = true;
              yamllint.enable = true;
              hadolint.enable = true;
            };

            packages = with pkgs; [
              gnumake

              yq-go
              jq

              opensc
              softhsm

              kind
              kubectl
              kustomize
              kubernetes-helm
              helm-docs

              golangci-lint
              yamllint
              hadolint
            ] ++ [
              self'.packages.licensei
            ];

            scripts = {
              versions.exec = ''
                go version
                golangci-lint version
                kind version
                kubectl version --client
                echo kustomize $(kustomize version)
                echo helm $(helm version --short)
              '';
            };

            enterShell = ''
              versions
            '';

            # https://github.com/cachix/devenv/issues/528#issuecomment-1556108767
            containers = pkgs.lib.mkForce { };
          };

          ci = devenv.shells.default;
        };

        packages = {
          # TODO: create flake in source repo
          licensei = pkgs.buildGoModule rec {
            pname = "licensei";
            version = "0.8.0";

            src = pkgs.fetchFromGitHub {
              owner = "goph";
              repo = "licensei";
              rev = "v${version}";
              sha256 = "sha256-Pvjmvfk0zkY2uSyLwAtzWNn5hqKImztkf8S6OhX8XoM=";
            };

            vendorHash = "sha256-ZIpZ2tPLHwfWiBywN00lPI1R7u7lseENIiybL3+9xG8=";

            subPackages = [ "cmd/licensei" ];

            ldflags = [
              "-w"
              "-s"
              "-X main.version=v${version}"
            ];
          };

          vault = pkgs.buildGoModule rec {
            pname = "vault";
            version = "1.14.8";

            src = pkgs.fetchFromGitHub {
              owner = "hashicorp";
              repo = "vault";
              rev = "v${version}";
              sha256 = "sha256-sGCODCBgsxyr96zu9ntPmMM/gHVBBO+oo5+XsdbCK4E=";
            };

            vendorHash = "sha256-zpHjZjgCgf4b2FAJQ22eVgq0YGoVvxGYJ3h/3ZRiyrQ=";

            proxyVendor = true;

            subPackages = [ "." ];

            tags = [ "vault" ];
            ldflags = [
              "-s"
              "-w"
              "-X github.com/hashicorp/vault/sdk/version.GitCommit=${src.rev}"
              "-X github.com/hashicorp/vault/sdk/version.Version=${version}"
              "-X github.com/hashicorp/vault/sdk/version.VersionPrerelease="
            ];
          };
        };
      };
    };
}
