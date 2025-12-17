import "pe"

rule MAL_Compromised_Cert_Oyster_GlobalSign_03401D78C301D8B05979084B {
   meta:
      description         = "Detects Oyster with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-07"
      version             = "1.0"

      hash                = "d32b4924143948935a74f03ae921a4c2efa4a94848d49274208e7007c0102f73"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "BLUS CONSULTING LLP"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "03:40:1d:78:c3:01:d8:b0:59:79:08:4b"
      cert_thumbprint     = "42FE654215B0D1046BDA7B5CD3A9B372449F9844"
      cert_valid_from     = "2025-08-07"
      cert_valid_to       = "2026-08-08"

      country             = "IN"
      state               = "Delhi"
      locality            = "New Delhi"
      email               = "ceoblusconsulting@gmail.com"
      rdn_serial_number   = "AAS-4006"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "03:40:1d:78:c3:01:d8:b0:59:79:08:4b"
      )
}
