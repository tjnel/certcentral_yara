import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_33000672B8B19DE992389240140000000672B8 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-09"
      version             = "1.0"

      hash                = "a380fcaa1ff910f507ee16a65efba06940e62223a077e0c1e7d8ade2407a230d"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Next-Gen Supplements Inc."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:06:72:b8:b1:9d:e9:92:38:92:40:14:00:00:00:06:72:b8"
      cert_thumbprint     = "CF72B637E6D1513555903408AA088BFB92C8713C"
      cert_valid_from     = "2025-12-09"
      cert_valid_to       = "2025-12-12"

      country             = "CA"
      state               = "Ontario"
      locality            = "Mississauga"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:06:72:b8:b1:9d:e9:92:38:92:40:14:00:00:00:06:72:b8"
      )
}
