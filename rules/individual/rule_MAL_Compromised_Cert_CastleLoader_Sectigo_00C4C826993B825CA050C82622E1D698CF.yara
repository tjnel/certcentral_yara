import "pe"

rule MAL_Compromised_Cert_CastleLoader_Sectigo_00C4C826993B825CA050C82622E1D698CF {
   meta:
      description         = "Detects CastleLoader with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-23"
      version             = "1.0"

      hash                = "aaf8b6441e239acade66d3f60fae59ef4f426dc14768ee7530ccbdcd61ef6e4e"
      malware             = "CastleLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "This is an initial access tool that is frequenty used to load infostealers or remote access tools, sold as Malware-as-a-Service: https://www.ibm.com/think/x-force/dissecting-castlebot-maas-operation"

      signer              = "Flight 041 LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV E36"
      cert_serial         = "00:c4:c8:26:99:3b:82:5c:a0:50:c8:26:22:e1:d6:98:cf"
      cert_thumbprint     = "2589C24E57D4BCF58A9B1168944826A8DE84EBA7"
      cert_valid_from     = "2025-10-23"
      cert_valid_to       = "2026-10-23"

      country             = "US"
      state               = "Arizona"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV E36" and
         sig.serial == "00:c4:c8:26:99:3b:82:5c:a0:50:c8:26:22:e1:d6:98:cf"
      )
}
