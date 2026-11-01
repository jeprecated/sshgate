{ pkgs, ... }:

{
  packages = [ pkgs.go_1_26 ];

  scripts = {
    fmt.exec = "gofmt -w .";
    test.exec = "go test ./...";
    build.exec = ''
      mkdir -p ./bin
      go build -o ./bin/sshgate
    '';
    install-local.exec = ''
      mkdir -p "$HOME/.local/bin"
      go build -o "$HOME/.local/bin/sshgate" ./
    '';
    check.exec = ''
      gofmt -w .
      go test ./...
    '';
  };

  enterTest = ''
    go test ./...
  '';
}
