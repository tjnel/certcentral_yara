import "pe"

rule MAL_Compromised_Cert_Crazy_Evil_Traffer_Team_Entrust_00C4B1716739E14C2FCB35D39D49ACB971 {
   meta:
      description         = "Detects Crazy Evil Traffer Team with compromised cert (Entrust)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-05"
      version             = "1.0"

      hash                = "6130a8fda1672a1c74fd9a401324cc26eb72c0b24fff308fb9987f9e9bf3f390"
      malware             = "Crazy Evil Traffer Team"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "REDSTRIKEVN COMPANY LIMITED"
      cert_issuer_short   = "Entrust"
      cert_issuer         = "Entrust Extended Validation Code Signing CA - EVCS2"
      cert_serial         = "00:c4:b1:71:67:39:e1:4c:2f:cb:35:d3:9d:49:ac:b9:71"
      cert_thumbprint     = "93137F64B4E0418CC67BE7A3268851A2CF7D88B3"
      cert_valid_from     = "2025-03-05"
      cert_valid_to       = "2026-03-05"

      country             = "VN"
      state               = "???"
      locality            = "Hồ Chí Minh"
      email               = "???"
      rdn_serial_number   = "0318798119"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Entrust Extended Validation Code Signing CA - EVCS2" and
         sig.serial == "00:c4:b1:71:67:39:e1:4c:2f:cb:35:d3:9d:49:ac:b9:71"
      )
}
