{ pkgs, config, ... }:

let
  # Tools that are not in nixpkgs. They are installed with `go install` into
  # $GOBIN at these pinned versions.
  goTools = {
    "github.com/go-gremlins/gremlins/cmd/gremlins" = "v0.6.0";
    "github.com/rillig/gobco" = "v1.3.4";
    "golang.org/x/perf/cmd/benchstat" = "v0.0.0-20261009192801-be2c69fb417e";
  };
  goInstallLines = builtins.concatStringsSep "\n" (
    builtins.attrValues (
      builtins.mapAttrs (path: version: ''
        name=${baseNameOf path}
        if [ "$(cat "$GOBIN/.$name.version" 2>/dev/null)" != "${version}" ]; then
          echo "Installing $name ${version}"
          go install ${path}@${version} && echo "${version}" > "$GOBIN/.$name.version"
        fi
      '') goTools
    )
  );
in
{
  languages.go.enable = true;

  packages = [
    pkgs.gcc # cgo, required by `go test -race`
    pkgs.golangci-lint # SpotBugs and CheckStyle slots
    pkgs.go-tools # staticcheck
    pkgs.gosec
    pkgs.revive
    pkgs.gocyclo
    pkgs.gofumpt
    (pkgs.python3.withPackages (p: [ p.cryptography ])) # testdata/gen.py
  ];

  env.GOBIN = "${config.devenv.state}/gobin";

  enterShell = ''
    export PATH="$GOBIN:$PATH"
    mkdir -p "$GOBIN" reports
    ${goInstallLines}
  '';

  scripts = {
    vvs-golden.exec = ''python3 testdata/gen.py'';
    vvs-test.exec = ''go test -race "$@" ./...'';
    vvs-lint.exec = ''
      golangci-lint run ./... | tee reports/lint.txt
      gocyclo -over 10 . | tee reports/gocyclo.txt
    '';
    vvs-cover.exec = ''
      go test -covermode=atomic -coverprofile=reports/cover.out ./...
      go tool cover -func=reports/cover.out | tee reports/cover.txt
      go tool cover -html=reports/cover.out -o reports/cover.html
    '';
    vvs-gobco.exec = ''gobco "$@" . | tee reports/gobco.txt'';
    vvs-bench.exec = ''
      go test -run '^$' -bench . -benchmem -count 10 "$@" ./... | tee reports/bench.txt
      benchstat reports/bench.txt
    '';
    vvs-fuzz.exec = ''
      target="''${1:?usage: vvs-fuzz FuzzName [duration]}"
      go test -run '^$' -fuzz "^$target\$" -fuzztime "''${2:-60s}" .
    '';
    vvs-mutate.exec = ''gremlins unleash "$@" | tee reports/mutation.txt'';
  };

  enterTest = ''
    go version
    golangci-lint version
    staticcheck -version
    gremlins --version
    command -v benchstat gobco
    gcc --version
    go vet ./...
  '';
}
