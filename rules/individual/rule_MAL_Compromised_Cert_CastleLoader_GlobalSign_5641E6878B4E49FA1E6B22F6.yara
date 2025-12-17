import "pe"

rule MAL_Compromised_Cert_CastleLoader_GlobalSign_5641E6878B4E49FA1E6B22F6 {
   meta:
      description         = "Detects CastleLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-01"
      version             = "1.0"

      hash                = "d9df71bce0b1037709a0732b7a53d4bacd0455a6abf1b7abe6fba74b6039a5a3"
      malware             = "CastleLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "This is an initial access tool that is frequenty used to load infostealers or remote access tools, sold as Malware-as-a-Service: https://www.ibm.com/think/x-force/dissecting-castlebot-maas-operation"

      signer              = "LLC Importer"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "56:41:e6:87:8b:4e:49:fa:1e:6b:22:f6"
      cert_thumbprint     = "E51A7393AC656E027240528C95F64568ED72D3AF"
      cert_valid_from     = "2025-05-01"
      cert_valid_to       = "2026-05-02"

      country             = "RU"
      state               = "Moscow"
      locality            = "Kommunarka"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "56:41:e6:87:8b:4e:49:fa:1e:6b:22:f6"
      )
}
