{
  config,
  lib,
  pkgs,
  self,
  ...
}:
let
  cfg = config.services.fido2-hid-bridge;
in
{
  options.services.fido2-hid-bridge = {
    enable = lib.mkEnableOption "the fido2-hid-bridge service";

    backend = lib.mkOption {
      type = lib.types.enum [
        "pcsc"
        "tcp"
      ];
      default = "pcsc";
      description = ''
        Authenticator backend to use.
        - `pcsc`: local PC/SC smartcard reader (default)
        - `tcp`: remote authenticator over TCP (e.g. Android phone with NFC dongle)
      '';
    };

    tcp = {
      port = lib.mkOption {
        type = lib.types.port;
        default = 28437;
        description = "TCP port to listen on (tcp backend only).";
      };

      openFirewall = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Whether to open the firewall for the TCP port.";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    # Auto-enable pcscd when using the PC/SC backend
    services.pcscd.enable = lib.mkIf (cfg.backend == "pcsc") (lib.mkDefault true);

    # Open firewall when requested
    networking.firewall.allowedTCPPorts = lib.mkIf cfg.tcp.openFirewall [
      cfg.tcp.port
    ];

    systemd.services.fido2-hid-bridge = {
      description = "FIDO2 to HID bridge";
      after = [
        "syslog.target"
        "network.target"
        "local-fs.target"
      ] ++ lib.optional (cfg.backend == "pcsc") "pcscd.service";
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "simple";
        ExecStart =
          if cfg.backend == "tcp" then
            "${self.packages.${pkgs.system}.default}/bin/fido2-hid-bridge --backend tcp --port ${toString cfg.tcp.port}"
          else
            "${self.packages.${pkgs.system}.default}/bin/fido2-hid-bridge";
      };
    };
  };
}
