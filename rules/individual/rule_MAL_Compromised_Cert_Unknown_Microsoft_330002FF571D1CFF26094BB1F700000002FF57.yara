import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_330002FF571D1CFF26094BB1F700000002FF57 {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-16"
      version             = "1.0"

      hash                = "414eeb3607eacbef7111b91a6695cb44b5256051ef4948a5d60df4cdc98946db"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "益林 陈"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:02:ff:57:1d:1c:ff:26:09:4b:b1:f7:00:00:00:02:ff:57"
      cert_thumbprint     = "A06A39E596121A5FA81850A436A80FB0AE9BEBC9"
      cert_valid_from     = "2025-03-16"
      cert_valid_to       = "2025-03-19"

      country             = "CN"
      state               = "Anhui"
      locality            = "安庆市"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:02:ff:57:1d:1c:ff:26:09:4b:b1:f7:00:00:00:02:ff:57"
      )
}
