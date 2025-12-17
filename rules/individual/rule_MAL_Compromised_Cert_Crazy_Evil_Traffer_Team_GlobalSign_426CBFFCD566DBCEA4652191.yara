import "pe"

rule MAL_Compromised_Cert_Crazy_Evil_Traffer_Team_GlobalSign_426CBFFCD566DBCEA4652191 {
   meta:
      description         = "Detects Crazy Evil Traffer Team with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-26"
      version             = "1.0"

      hash                = "c04e7662421eac7bd7b6a4c7ee6dc114a18fa3504d204db6284fb54a60c0708b"
      malware             = "Crazy Evil Traffer Team"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "REDSTRIKEVN COMPANY LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "42:6c:bf:fc:d5:66:db:ce:a4:65:21:91"
      cert_thumbprint     = "8962B26B47CA584B1AFDD2734E280D7E8701F2F6"
      cert_valid_from     = "2025-02-26"
      cert_valid_to       = "2026-02-20"

      country             = "VN"
      state               = "Hồ Chí Minh"
      locality            = "Hồ Chí Minh"
      email               = "???"
      rdn_serial_number   = "0318798119"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "42:6c:bf:fc:d5:66:db:ce:a4:65:21:91"
      )
}
