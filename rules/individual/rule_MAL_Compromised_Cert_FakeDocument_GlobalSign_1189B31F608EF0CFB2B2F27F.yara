import "pe"

rule MAL_Compromised_Cert_FakeDocument_GlobalSign_1189B31F608EF0CFB2B2F27F {
   meta:
      description         = "Detects FakeDocument with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-28"
      version             = "1.0"

      hash                = "9993ae862e80930fc460454ed36f9811ab106eeb4731a6f319b3f9a09b284ae1"
      malware             = "FakeDocument"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MOUNI MEDIA PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "11:89:b3:1f:60:8e:f0:cf:b2:b2:f2:7f"
      cert_thumbprint     = "70E6A90E5AC6736029D1030E005F7A905A27C855"
      cert_valid_from     = "2025-10-28"
      cert_valid_to       = "2026-10-29"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "11:89:b3:1f:60:8e:f0:cf:b2:b2:f2:7f"
      )
}
