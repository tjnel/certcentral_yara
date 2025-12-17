import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330005750BD2CF0F3CFC3D4FC300000005750B {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-13"
      version             = "1.0"

      hash                = "5fbee3b9e0286e54981bb7794d72b6a3e96a57eed1f7d2f8b4fcd6eb7a1a6df1"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "AUTOMOBILITY ENTERPRISES INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:05:75:0b:d2:cf:0f:3c:fc:3d:4f:c3:00:00:00:05:75:0b"
      cert_thumbprint     = "A1114DF146F9B0CEAB4B995E6F25B959EE7001AE"
      cert_valid_from     = "2025-09-13"
      cert_valid_to       = "2025-09-16"

      country             = "CA"
      state               = "Ontario"
      locality            = "Windsor"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:05:75:0b:d2:cf:0f:3c:fc:3d:4f:c3:00:00:00:05:75:0b"
      )
}
