import "pe"

rule MAL_Compromised_Cert_Crazy_Evil_Traffer_Team_Microsoft_3300021FFB7A57E64367C9F45A000000021FFB {
   meta:
      description         = "Detects Crazy Evil Traffer Team with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-18"
      version             = "1.0"

      hash                = "53e16a1e81d087bd93345f55f29a0cc4fd3e665023ccc708eef696e0ecb56452"
      malware             = "Crazy Evil Traffer Team"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "益林 陈"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:02:1f:fb:7a:57:e6:43:67:c9:f4:5a:00:00:00:02:1f:fb"
      cert_thumbprint     = "1858EDFE08C5F267DE706CB298DB26BCD57B400A"
      cert_valid_from     = "2025-03-18"
      cert_valid_to       = "2025-03-21"

      country             = "CN"
      state               = "Anhui"
      locality            = "安庆市"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:02:1f:fb:7a:57:e6:43:67:c9:f4:5a:00:00:00:02:1f:fb"
      )
}
