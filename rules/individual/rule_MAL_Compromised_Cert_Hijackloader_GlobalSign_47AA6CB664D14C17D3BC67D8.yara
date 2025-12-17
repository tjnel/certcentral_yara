import "pe"

rule MAL_Compromised_Cert_Hijackloader_GlobalSign_47AA6CB664D14C17D3BC67D8 {
   meta:
      description         = "Detects Hijackloader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-25"
      version             = "1.0"

      hash                = "7b108d249f03bbe74315c10f6bfe9332ede6d21d4e8814385a35a57a9118c888"
      malware             = "Hijackloader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "C.E. Holding ApS"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "47:aa:6c:b6:64:d1:4c:17:d3:bc:67:d8"
      cert_thumbprint     = "13E3C8CAF22AABBAD0A370F4B87E3AF1FB0F916A"
      cert_valid_from     = "2025-09-25"
      cert_valid_to       = "2026-09-26"

      country             = "DK"
      state               = "Skanderborg"
      locality            = "Skanderborg"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "47:aa:6c:b6:64:d1:4c:17:d3:bc:67:d8"
      )
}
