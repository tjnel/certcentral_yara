import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_330001B66C239653B84C37EA0900000001B66C {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-16"
      version             = "1.0"

      hash                = "fb2c4271b507256b7472016f29a6da068d394995dad0a9965ec8dc19b026f44c"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "葛 香牛"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:01:b6:6c:23:96:53:b8:4c:37:ea:09:00:00:00:01:b6:6c"
      cert_thumbprint     = "EA75F2482ACD340FDBE627ABA3ED93E2C53CEEFA"
      cert_valid_from     = "2025-02-16"
      cert_valid_to       = "2025-02-19"

      country             = "CN"
      state               = "Jiangsu"
      locality            = "泗阳县"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:01:b6:6c:23:96:53:b8:4c:37:ea:09:00:00:00:01:b6:6c"
      )
}
