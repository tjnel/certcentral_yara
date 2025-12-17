import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_0868787EBCFA854B61CD6909 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-29"
      version             = "1.0"

      hash                = "3d8e2e52061f8b1d92487544d08a11e91c9d90a75fa7a381195618c88f0e75ed"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Tactics-N"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "08:68:78:7e:bc:fa:85:4b:61:cd:69:09"
      cert_thumbprint     = "8BF78202F72DAA0843987AA50E3ACC5D1B58756D"
      cert_valid_from     = "2025-09-29"
      cert_valid_to       = "2026-06-06"

      country             = "RU"
      state               = "Novosibirsk Oblast"
      locality            = "Novosibirsk"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "08:68:78:7e:bc:fa:85:4b:61:cd:69:09"
      )
}
