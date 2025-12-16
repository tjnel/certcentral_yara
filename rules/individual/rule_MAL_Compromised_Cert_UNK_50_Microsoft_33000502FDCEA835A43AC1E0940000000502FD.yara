import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_33000502FDCEA835A43AC1E0940000000502FD {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-24"
      version             = "1.0"

      hash                = "5dae3f4a93f253c363d98b7f6873a5a3f250e763682bef06ca4fc2d84ae82189"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "IGNITE ARTIST MOVEMENT"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:05:02:fd:ce:a8:35:a4:3a:c1:e0:94:00:00:00:05:02:fd"
      cert_thumbprint     = "C49C6B531C60F7EA8579FBA34A16EF16E82E097F"
      cert_valid_from     = "2025-10-24"
      cert_valid_to       = "2025-10-27"

      country             = "CA"
      state               = "Ontario"
      locality            = "Toronto"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:05:02:fd:ce:a8:35:a4:3a:c1:e0:94:00:00:00:05:02:fd"
      )
}
