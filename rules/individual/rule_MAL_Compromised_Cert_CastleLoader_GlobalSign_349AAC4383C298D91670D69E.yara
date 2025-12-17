import "pe"

rule MAL_Compromised_Cert_CastleLoader_GlobalSign_349AAC4383C298D91670D69E {
   meta:
      description         = "Detects CastleLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-23"
      version             = "1.0"

      hash                = "64562a0f1eabfcfb754426020021da69fe31bb551a653d143d75649252c61050"
      malware             = "CastleLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "This is an initial access tool that is frequenty used to load infostealers or remote access tools, sold as Malware-as-a-Service: https://www.ibm.com/think/x-force/dissecting-castlebot-maas-operation"

      signer              = "TENDENCE LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "34:9a:ac:43:83:c2:98:d9:16:70:d6:9e"
      cert_thumbprint     = "A70F01C28A27B5F78A5381F75A858C81C191756A"
      cert_valid_from     = "2025-09-23"
      cert_valid_to       = "2025-12-25"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "34:9a:ac:43:83:c2:98:d9:16:70:d6:9e"
      )
}
