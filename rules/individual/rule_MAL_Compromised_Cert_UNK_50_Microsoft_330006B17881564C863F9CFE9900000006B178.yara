import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330006B17881564C863F9CFE9900000006B178 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-13"
      version             = "1.0"

      hash                = "02126326250b28820ccdaf2b9c4ba2d14f6dbeff906f17ee72ba141fcf45263b"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Next-Gen Supplements Inc."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:06:b1:78:81:56:4c:86:3f:9c:fe:99:00:00:00:06:b1:78"
      cert_thumbprint     = "E79D79F5CFAD917C9E411E509C325F38946F6261"
      cert_valid_from     = "2025-12-13"
      cert_valid_to       = "2025-12-16"

      country             = "CA"
      state               = "Ontario"
      locality            = "Mississauga"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:06:b1:78:81:56:4c:86:3f:9c:fe:99:00:00:00:06:b1:78"
      )
}
