import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_GlobalSign_3B7EAC8B20F3EDCB557300BE {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-17"
      version             = "1.0"

      hash                = "aec4e5e79e5690c6f8f97334da9aa9898fb5ea68c6458efee70a45a88863c925"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "LLC Service Stroy TK"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3b:7e:ac:8b:20:f3:ed:cb:55:73:00:be"
      cert_thumbprint     = "3F6BE09D1813092FD3AC7D3C28D3600343426976"
      cert_valid_from     = "2025-04-17"
      cert_valid_to       = "2026-04-18"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3b:7e:ac:8b:20:f3:ed:cb:55:73:00:be"
      )
}
