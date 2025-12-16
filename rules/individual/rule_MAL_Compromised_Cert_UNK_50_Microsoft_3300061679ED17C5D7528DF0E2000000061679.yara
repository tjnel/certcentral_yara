import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_3300061679ED17C5D7528DF0E2000000061679 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-02"
      version             = "1.0"

      hash                = "e132be181eb9a803a95b4009de529fa1db1ccc7b8fc8b19dc17d1b9eb26bac14"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "THROGGS NECK PETS INCORPORATED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:06:16:79:ed:17:c5:d7:52:8d:f0:e2:00:00:00:06:16:79"
      cert_thumbprint     = "7F67320BA860CC72D831991AC5DB81CEA0468DD1"
      cert_valid_from     = "2025-11-02"
      cert_valid_to       = "2025-11-05"

      country             = "US"
      state               = "New York"
      locality            = "BRONX"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:06:16:79:ed:17:c5:d7:52:8d:f0:e2:00:00:00:06:16:79"
      )
}
