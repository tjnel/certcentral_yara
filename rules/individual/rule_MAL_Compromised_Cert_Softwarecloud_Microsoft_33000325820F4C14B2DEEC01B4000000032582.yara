import "pe"

rule MAL_Compromised_Cert_Softwarecloud_Microsoft_33000325820F4C14B2DEEC01B4000000032582 {
   meta:
      description         = "Detects Softwarecloud with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-06"
      version             = "1.0"

      hash                = "2ef83dbf97a533ff27e32dd81471db5e9f0a8c2910f1854c161e22aa8d9a7722"
      malware             = "Softwarecloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "Gaduha Technologies Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:03:25:82:0f:4c:14:b2:de:ec:01:b4:00:00:00:03:25:82"
      cert_thumbprint     = "BD1B8C5029BEA29EB58A22190D6181CED9A31114"
      cert_valid_from     = "2025-06-06"
      cert_valid_to       = "2025-06-09"

      country             = "US"
      state               = "Texas"
      locality            = "Irving"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:03:25:82:0f:4c:14:b2:de:ec:01:b4:00:00:00:03:25:82"
      )
}
