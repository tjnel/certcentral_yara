import "pe"

rule MAL_Compromised_Cert_CastleLoader_GlobalSign_1916747D5AC1ABEC2D20DB84 {
   meta:
      description         = "Detects CastleLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-27"
      version             = "1.0"

      hash                = "ce6068417aeeb4d1379e58322d8cbcc1ebbacd5c1bef7de5b3e17be725c281a6"
      malware             = "CastleLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "This is an initial access tool that is frequenty used to load infostealers or remote access tools, sold as Malware-as-a-Service: https://www.ibm.com/think/x-force/dissecting-castlebot-maas-operation"

      signer              = "STALKER LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "19:16:74:7d:5a:c1:ab:ec:2d:20:db:84"
      cert_thumbprint     = "B6E685D6EAADE42B2AC46BB9F55665A1E4C63796"
      cert_valid_from     = "2025-09-27"
      cert_valid_to       = "2025-10-23"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "19:16:74:7d:5a:c1:ab:ec:2d:20:db:84"
      )
}
