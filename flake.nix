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

        devShells = {
          release = pkgs.mkShell {
            buildInputs = with pkgs; [
              git
              go_1_20

              goreleaser

              pkg-config

              opensc
              softhsm

              pkgsCross.aarch64-darwin.buildPackages.clang
              # pkgsCross.aarch64-darwin.buildPackages.stdenv.cc.bintools
              # pkgsCross.aarch64-darwin.buildPackages.bintools

              # darwin.apple_sdk.frameworks.CoreFoundation
              # darwin.apple_sdk.frameworks.Security
            ];
          };
        };
        devenv.shells = {
          default = {
            languages = {
              go.enable = true;
            };

            services = {
              vault.enable = true;
            };

            pre-commit.hooks = {
              nixpkgs-fmt.enable = true;
              yamllint.enable = true;
              hadolint.enable = true;
            };

            packages = with pkgs; [
              gnumake

              pkg-config
              pkgsCross.gnu64.buildPackages.gcc
              pkgsCross.aarch64-multiplatform.buildPackages.gcc
              # pkgsCross.x86_64-darwin.buildPackages.gcc
              # pkgsCross.aarch64-darwin.buildPackages.gcc

              pkgsCross.aarch64-darwin.buildPackages.clang
              pkgsCross.aarch64-darwin.buildPackages.stdenv.cc.bintools
              pkgsCross.aarch64-darwin.buildPackages.bintools

              darwin.apple_sdk.frameworks.CoreFoundation
              darwin.apple_sdk.frameworks.Security

              golangci-lint
              goreleaser

              opensc
              softhsm

              kind
              kubectl
              kustomize
              kubernetes-helm
              helm-docs

              yamllint
              hadolint
            ] ++ [
              self'.packages.licensei
              self'.packages.xgo
            ];

            scripts = {
              versions.exec = ''
                go version
                golangci-lint version
                echo controller-gen $(controller-gen --version)
                kind version
                kubectl version --client
                echo kustomize $(kustomize version --short)
                echo helm $(helm version --short)
              '';
            };

            enterShell = ''
              versions

              export CGO_CFLAGS_for_darwin_arm64="$CGO_CFLAGS $(go env CGO_CFLAGS) $(cat ${pkgs.pkgsCross.aarch64-darwin.buildPackages.stdenv.cc}/nix-support/{cc,libc}-cflags | awk 1 ORS=' ')"
              export CGO_LDFLAGS_for_darwin_arm64="$CGO_LDFLAGS $(go env CGO_LDFLAGS) $(cat ${pkgs.pkgsCross.aarch64-darwin.buildPackages.stdenv.cc}/nix-support/{cc,libc}-ldflags | awk 1 ORS=' ') -F${pkgs.darwin.apple_sdk.frameworks.CoreFoundation}/Library/Frameworks -F${pkgs.darwin.apple_sdk.frameworks.Security}/Library/Frameworks"
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

            vendorSha256 = "sha256-ZIpZ2tPLHwfWiBywN00lPI1R7u7lseENIiybL3+9xG8=";

            subPackages = [ "cmd/licensei" ];

            ldflags = [
              "-w"
              "-s"
              "-X main.version=v${version}"
            ];
          };

          xgo = pkgs.buildGoModule rec {
            pname = "xgo";
            version = "0.28.0";

            src = pkgs.fetchFromGitHub {
              owner = "crazy-max";
              repo = "xgo";
              rev = "v${version}";
              sha256 = "sha256-chkmQF5xSccHuY5yH9oSn243E92EmvKCGQdAEy3eMXw=";
            };

            vendorSha256 = null;

            subPackages = [ "." ];
          };
        };
      };
    };
}
