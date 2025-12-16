import "pe"

rule MAL_Compromised_Cert_Softwarecloud_Microsoft_3300039A19B6113A899F2279F7000000039A19 {
   meta:
      description         = "Detects Softwarecloud with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-16"
      version             = "1.0"

      hash                = "9216137b680651f7780e26151cf0925177f1553248a7f886d9a62c3e29e6c1ce"
      malware             = "Softwarecloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "CASCO ASSOCIATES, INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:03:9a:19:b6:11:3a:89:9f:22:79:f7:00:00:00:03:9a:19"
      cert_thumbprint     = "06A9B0919F86A26C35B84C05613DF6F2CAEEF92E"
      cert_valid_from     = "2025-07-16"
      cert_valid_to       = "2025-07-19"

      country             = "US"
      state               = "New York"
      locality            = "Manhasset"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:03:9a:19:b6:11:3a:89:9f:22:79:f7:00:00:00:03:9a:19"
      )
}
