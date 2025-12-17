import "pe"

rule MAL_Compromised_Cert_Crazy_Evil_Traffer_Team_GlobalSign_36D5370B083DB9016FC1D1FE {
   meta:
      description         = "Detects Crazy Evil Traffer Team with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-15"
      version             = "1.0"

      hash                = "30e6559bc1a972a70d633d9fc00e50e0b369358664d3e41e47123d74eec59b1e"
      malware             = "Crazy Evil Traffer Team"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Yongji Jiecheng Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "36:d5:37:0b:08:3d:b9:01:6f:c1:d1:fe"
      cert_thumbprint     = "9D54D7FEF240079C18A6923BE6A312B7F6D98283"
      cert_valid_from     = "2025-05-15"
      cert_valid_to       = "2026-05-16"

      country             = "CN"
      state               = "Shanxi"
      locality            = "Yuncheng"
      email               = "???"
      rdn_serial_number   = "91140881MAD1DCC017"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "36:d5:37:0b:08:3d:b9:01:6f:c1:d1:fe"
      )
}
