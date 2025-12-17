import "pe"

rule MAL_Compromised_Cert_Crazy_Evil_Traffer_Team_GlobalSign_252075025C25BACBAC23B4BA {
   meta:
      description         = "Detects Crazy Evil Traffer Team with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-23"
      version             = "1.0"

      hash                = "1df2c7b7ad92ae543ffb68afcd54301be97f070ed2d1a71898812dd8d8a33ae8"
      malware             = "Crazy Evil Traffer Team"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Micro Hat Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "25:20:75:02:5c:25:ba:cb:ac:23:b4:ba"
      cert_thumbprint     = "589D8A29339A343EFE1DAE8E44EDE85B615BE0FA"
      cert_valid_from     = "2024-09-23"
      cert_valid_to       = "2025-09-24"

      country             = "CN"
      state               = "Anhui"
      locality            = "Hefei"
      email               = "???"
      rdn_serial_number   = "91340100083694107X"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "25:20:75:02:5c:25:ba:cb:ac:23:b4:ba"
      )
}
