import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330004E5855BA4C7024078696F00000004E585 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-19"
      version             = "1.0"

      hash                = "bea1aed8853dbf86cc03a6abb90949a93e26dd7b09bbf5b2bf2d3fc065a2ef95"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "IGNITE ARTIST MOVEMENT"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:04:e5:85:5b:a4:c7:02:40:78:69:6f:00:00:00:04:e5:85"
      cert_thumbprint     = "E09327FC7CFC577B001469177FE25F4057B2F72A"
      cert_valid_from     = "2025-10-19"
      cert_valid_to       = "2025-10-22"

      country             = "CA"
      state               = "Ontario"
      locality            = "Toronto"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:04:e5:85:5b:a4:c7:02:40:78:69:6f:00:00:00:04:e5:85"
      )
}
