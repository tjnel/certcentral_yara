import "pe"

rule MAL_Compromised_Cert_Crazy_Evil_Traffer_Team_Microsoft_33000306F23A9C36B302A577A30000000306F2 {
   meta:
      description         = "Detects Crazy Evil Traffer Team with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-19"
      version             = "1.0"

      hash                = "2240ccae318ec18f421d7b539b610abcda114edcd60e4da96e8ca7e502d9f6bd"
      malware             = "Crazy Evil Traffer Team"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "红火 罗"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:03:06:f2:3a:9c:36:b3:02:a5:77:a3:00:00:00:03:06:f2"
      cert_thumbprint     = "5B916BEF4113A6922213C52AE77A96676F23FEB2"
      cert_valid_from     = "2025-03-19"
      cert_valid_to       = "2025-03-22"

      country             = "CN"
      state               = "Yunnan"
      locality            = "昭通市"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:03:06:f2:3a:9c:36:b3:02:a5:77:a3:00:00:00:03:06:f2"
      )
}
