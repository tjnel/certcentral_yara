import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_33000536BE6C7D73B4A2FC97EF0000000536BE {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-14"
      version             = "1.0"

      hash                = "a0ae809ca1cb6cc1ef508bc1c9627c076761ac2a3cf3993fa9e63862a17d05b1"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "JAMES BARRIERE FOUNDATION FOR THE UNDERPRIVILEGED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:05:36:be:6c:7d:73:b4:a2:fc:97:ef:00:00:00:05:36:be"
      cert_thumbprint     = "B5C9A1498A887067A8E8F3EC1B5BBC75D7227F3E"
      cert_valid_from     = "2025-11-14"
      cert_valid_to       = "2025-11-17"

      country             = "CA"
      state               = "Québec"
      locality            = "MONTREAL"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:05:36:be:6c:7d:73:b4:a2:fc:97:ef:00:00:00:05:36:be"
      )
}
