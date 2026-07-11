{
  description = "Virtual USB-HID FIDO2 device that receives FIDO2 CTAP2.1 commands and forwards them to an attached authenticator.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    pyproject-nix = {
      url = "github:pyproject-nix/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    uv2nix = {
      url = "github:pyproject-nix/uv2nix";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    pyproject-build-systems = {
      url = "github:pyproject-nix/build-system-pkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.uv2nix.follows = "uv2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      uv2nix,
      pyproject-nix,
      pyproject-build-systems,
    }:
    let
      forAllSystems = nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          python = pkgs.python312;
          lib = nixpkgs.lib;

          # The upstream pyproject.toml uses poetry [tool.poetry] format.
          # uv2nix needs standard [project] format, so we override it.
          # This pyproject is self-contained: it's both the project metadata
          # AND the build config (setuptools), so uv2nix installs the
          # fido2_hid_bridge package itself into the venv.
          uvPyproject = pkgs.writeText "pyproject.toml" ''
            [project]
            name = "fido2-hid-bridge"
            version = "0.1.0"
            description = "Virtual USB-HID FIDO2 device"
            requires-python = ">=3.12"
            dependencies = ["uhid==0.0.1", "pyscard==2.3.1", "fido2[pcsc]>=2.1.1"]

            [project.scripts]
            fido2-hid-bridge = "fido2_hid_bridge.bridge:main"

            [build-system]
            requires = ["setuptools"]
            build-backend = "setuptools.build_meta"

            [tool.setuptools.packages.find]
            include = ["fido2_hid_bridge*"]
          '';

          # Build the source with the overridden pyproject.toml
          source = pkgs.runCommand "fido2-hid-bridge-src" { } ''
            mkdir $out/
            cp -r ${./fido2_hid_bridge} $out/fido2_hid_bridge
            cp ${uvPyproject} $out/pyproject.toml
            cp ${./uv.lock} $out/uv.lock
          '';

          workspace = uv2nix.lib.workspace.loadWorkspace { workspaceRoot = source; };
          overlay = workspace.mkPyprojectOverlay { sourcePreference = "wheel"; };
          pythonBase = pkgs.callPackage pyproject-nix.build.packages { inherit python; };
          pythonSet = pythonBase.overrideScope (
            lib.composeManyExtensions [
              pyproject-build-systems.overlays.wheel
              overlay
              (final: prev: {
                pyscard = prev.pyscard.overrideAttrs (old: {
                  nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [
                    pkgs.pkg-config
                    pkgs.swig
                    final.setuptools
                  ];
                  buildInputs = (old.buildInputs or [ ]) ++ [ pkgs.pcsclite ];
                });
              })
            ]
          );
        in
        {
          default = pythonSet.mkVirtualEnv "fido2-hid-bridge-env" workspace.deps.default;
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.uv
              pkgs.pcsclite
              pkgs.pkg-config
              pkgs.poetry
            ];
            env = {
              UV_PYTHON_DOWNLOADS = "never";
              UV_NO_SYNC = "true";
            };
            shellHook = ''
              unset PYTHONPATH
            '';
          };
        }
      );

      nixosModules.default = { pkgs, ... }: {
        imports = [ (import ./nix/module.nix) ];
        services.fido2-hid-bridge.package = self.packages.${pkgs.system}.default;
      };
    };
}
