{
  description = "Specht — unified vulnerability management platform (dev environment)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          go_1_26 # matches go.mod's go 1.26
          gopls
          gcc13  # cgo (pgx etc.) needs a C compiler on NixOS
          gofumpt
          golangci-lint # pre-commit hook runs staticcheck via golangci-lint
          git
          sqlc
          sonar-scanner-cli
          docker-client
          curl
          python3
          nodejs_26
          pnpm
          dprint
          oxlint # pre-commit oxlint mirror ships a glibc binary NixOS can't run — use the nixpkgs build
          prek
          hadolint
          gitleaks
        ];

        shellHook = ''
          echo "Specht dev shell — $(go version | awk '{print $3}') · sqlc $(sqlc version 2>/dev/null | awk '{print $2}')"
          echo "Hooks: prek run --all-files (NixOS-native oxlint + dprint from nixpkgs)"
          echo "Go LSP: make lsp-check · SonarQube: SONAR_ADMIN_PASSWORD=admin make sonar"
        '';
      };
    };
}
