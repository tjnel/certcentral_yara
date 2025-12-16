import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330005CF0655374B893F5E81FB00000005CF06 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-14"
      version             = "1.0"

      hash                = "5d89855c2ee1067ea43cba8ec65053695aa1cb846a31fbfd6a8e33b6ff62d3fb"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "IGNITE ARTIST MOVEMENT"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:05:cf:06:55:37:4b:89:3f:5e:81:fb:00:00:00:05:cf:06"
      cert_thumbprint     = "5C9647F9D94F3518B1A5514692AEA422CDFEAAD9"
      cert_valid_from     = "2025-10-14"
      cert_valid_to       = "2025-10-17"

      country             = "CA"
      state               = "Ontario"
      locality            = "Toronto"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:05:cf:06:55:37:4b:89:3f:5e:81:fb:00:00:00:05:cf:06"
      )
}
