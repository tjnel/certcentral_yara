import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_33000695549F4C6D731AE07807000000069554 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-19"
      version             = "1.0"

      hash                = "7ce29158a3c83fa9d4497b9d46c3b646e3c98806bfd115665e4eb2f4d29a28d5"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "EXCELLENCY HUB INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:06:95:54:9f:4c:6d:73:1a:e0:78:07:00:00:00:06:95:54"
      cert_thumbprint     = "13F75A74DCA2B3ECDAB1DA57E7D93F9A79D2BDD6"
      cert_valid_from     = "2025-12-19"
      cert_valid_to       = "2025-12-22"

      country             = "CA"
      state               = "Ontario"
      locality            = "MISSISSAUGA"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:06:95:54:9f:4c:6d:73:1a:e0:78:07:00:00:00:06:95:54"
      )
}
