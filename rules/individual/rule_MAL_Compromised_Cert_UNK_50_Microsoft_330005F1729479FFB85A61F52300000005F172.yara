import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330005F1729479FFB85A61F52300000005F172 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-25"
      version             = "1.0"

      hash                = "73aa0283c46a9a3b05a9f9480459d19eccbdec33b7ef10a341b0f0b72a4bb74f"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "DIGI-FUTURE INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:05:f1:72:94:79:ff:b8:5a:61:f5:23:00:00:00:05:f1:72"
      cert_thumbprint     = "80AA94838683743BB712815DB5A10880A45ED2B4"
      cert_valid_from     = "2025-10-25"
      cert_valid_to       = "2025-10-28"

      country             = "CA"
      state               = "Ontario"
      locality            = "OSHAWA"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:05:f1:72:94:79:ff:b8:5a:61:f5:23:00:00:00:05:f1:72"
      )
}
