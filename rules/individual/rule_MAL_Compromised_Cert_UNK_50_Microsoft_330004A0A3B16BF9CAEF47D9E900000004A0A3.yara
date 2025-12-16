import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330004A0A3B16BF9CAEF47D9E900000004A0A3 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-03"
      version             = "1.0"

      hash                = "43761d77921f37c8f8730610186eac17d18aaacc4ad51ec512e25ca953bb3426"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "IGNITE ARTIST MOVEMENT"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:04:a0:a3:b1:6b:f9:ca:ef:47:d9:e9:00:00:00:04:a0:a3"
      cert_thumbprint     = "E2369456FAD836C20E3E6E431C289FF3E91E6854"
      cert_valid_from     = "2025-10-03"
      cert_valid_to       = "2025-10-06"

      country             = "CA"
      state               = "Ontario"
      locality            = "Toronto"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:04:a0:a3:b1:6b:f9:ca:ef:47:d9:e9:00:00:00:04:a0:a3"
      )
}
