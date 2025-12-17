import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_GlobalSign_543A61A75B00D24BE9901085 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-16"
      version             = "1.0"

      hash                = "8f9abc7d4c506597867d65bb902ed8fca719e55e7173b9d5c82b0b30633bb84c"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "LLC PET"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "54:3a:61:a7:5b:00:d2:4b:e9:90:10:85"
      cert_thumbprint     = "0076727A360E455A67CAF5A9FC1B27EE9E02191D"
      cert_valid_from     = "2025-06-16"
      cert_valid_to       = "2026-06-17"

      country             = "RU"
      state               = "Kemerovo Oblast"
      locality            = "Kemerovo"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "54:3a:61:a7:5b:00:d2:4b:e9:90:10:85"
      )
}
