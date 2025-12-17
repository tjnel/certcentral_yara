import "pe"

rule MAL_Compromised_Cert_donut_GlobalSign_3B7EAC8B20F3EDCB557300BE {
   meta:
      description         = "Detects donut with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-17"
      version             = "1.0"

      hash                = "f581f89ed99982ebd1eb16913d9128d09655cfacf922b5c62697b36b3469872d"
      malware             = "donut"
      malware_type        = "Unknown"
      malware_notes       = ""

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
      rdn_serial_number   = "1177746889099"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3b:7e:ac:8b:20:f3:ed:cb:55:73:00:be"
      )
}
