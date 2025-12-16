import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_3300050381CFFB7CC9298CFA06000000050381 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-24"
      version             = "1.0"

      hash                = "aae2923d1e8207e22b4a1d80b8ef6e0892a5a936b1a6eaab524f889f84751383"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "DIGI-FUTURE INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:05:03:81:cf:fb:7c:c9:29:8c:fa:06:00:00:00:05:03:81"
      cert_thumbprint     = "95D89A34564A2A7953B9B457E5E98C9C77622D72"
      cert_valid_from     = "2025-10-24"
      cert_valid_to       = "2025-10-27"

      country             = "CA"
      state               = "Ontario"
      locality            = "OSHAWA"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:05:03:81:cf:fb:7c:c9:29:8c:fa:06:00:00:00:05:03:81"
      )
}
