import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330004D6BAE7BC440382EB85AB00000004D6BA {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-15"
      version             = "1.0"

      hash                = "d51fba7506ff0417aede5f557fea570ca7cdcd789e2b0c224478434e89665474"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "IGNITE ARTIST MOVEMENT"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:04:d6:ba:e7:bc:44:03:82:eb:85:ab:00:00:00:04:d6:ba"
      cert_thumbprint     = "0DE8CB37B36AE5B167077C7EBE31301093961FCB"
      cert_valid_from     = "2025-10-15"
      cert_valid_to       = "2025-10-18"

      country             = "CA"
      state               = "Ontario"
      locality            = "Toronto"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:04:d6:ba:e7:bc:44:03:82:eb:85:ab:00:00:00:04:d6:ba"
      )
}
