import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_33000516EAAA0A5669159912530000000516EA {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-01"
      version             = "1.0"

      hash                = "483c35e6be39edb99e21bd9f496c7d644651c7fda5a1ec66c95ea22ff82475a5"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "DIGI-FUTURE INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:05:16:ea:aa:0a:56:69:15:99:12:53:00:00:00:05:16:ea"
      cert_thumbprint     = "84949E65AFB428195932CB57BBF255F20BDD59AC"
      cert_valid_from     = "2025-11-01"
      cert_valid_to       = "2025-11-04"

      country             = "CA"
      state               = "Ontario"
      locality            = "OSHAWA"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:05:16:ea:aa:0a:56:69:15:99:12:53:00:00:00:05:16:ea"
      )
}
