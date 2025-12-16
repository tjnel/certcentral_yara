import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330004A8FCDD16B3741E8F880300000004A8FC {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-05"
      version             = "1.0"

      hash                = "ac3ae76eef76ee71fa460c2846da5efd0d9eb76ccb32c192d60d611040d411aa"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "IGNITE ARTIST MOVEMENT"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:04:a8:fc:dd:16:b3:74:1e:8f:88:03:00:00:00:04:a8:fc"
      cert_thumbprint     = "9CD750DD107519B4C856C18011FB7ECF681C8B1E"
      cert_valid_from     = "2025-10-05"
      cert_valid_to       = "2025-10-08"

      country             = "CA"
      state               = "Ontario"
      locality            = "Toronto"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:04:a8:fc:dd:16:b3:74:1e:8f:88:03:00:00:00:04:a8:fc"
      )
}
