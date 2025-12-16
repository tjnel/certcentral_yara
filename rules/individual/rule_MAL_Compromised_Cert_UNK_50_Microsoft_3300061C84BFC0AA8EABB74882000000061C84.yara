import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_3300061C84BFC0AA8EABB74882000000061C84 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-03"
      version             = "1.0"

      hash                = "82f2ff57ddea19e800d00c31e8625c39582b483c62e35d9f83de9327e880b044"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "DIGI-FUTURE INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:06:1c:84:bf:c0:aa:8e:ab:b7:48:82:00:00:00:06:1c:84"
      cert_thumbprint     = "A3EF800D1C5BBEF950501DA09051D2A78B47FC00"
      cert_valid_from     = "2025-11-03"
      cert_valid_to       = "2025-11-06"

      country             = "CA"
      state               = "Ontario"
      locality            = "OSHAWA"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:06:1c:84:bf:c0:aa:8e:ab:b7:48:82:00:00:00:06:1c:84"
      )
}
