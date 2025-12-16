import "pe"

rule MAL_Compromised_Cert_Crazy_Evil_Traffer_Team_Entrust_00C25308E33EE5E814D2E3054026033F4C {
   meta:
      description         = "Detects Crazy Evil Traffer Team with compromised cert (Entrust)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-20"
      version             = "1.0"

      hash                = "aae36559d8f600cee0f77dfa2e1bd88b58c908fb4190001d180ebb2ba1d9802c"
      malware             = "Crazy Evil Traffer Team"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "NEXTGENSOFTWARE COMPANY LIMITED"
      cert_issuer_short   = "Entrust"
      cert_issuer         = "Entrust Extended Validation Code Signing CA - EVCS2"
      cert_serial         = "00:c2:53:08:e3:3e:e5:e8:14:d2:e3:05:40:26:03:3f:4c"
      cert_thumbprint     = "2B301191AA9E1D2C8E3EEFD38B6EB1952B1FCE88"
      cert_valid_from     = "2025-01-20"
      cert_valid_to       = "2026-01-20"

      country             = "VN"
      state               = "???"
      locality            = "Hồ Chí Minh"
      email               = "???"
      rdn_serial_number   = "0318797820"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Entrust Extended Validation Code Signing CA - EVCS2" and
         sig.serial == "00:c2:53:08:e3:3e:e5:e8:14:d2:e3:05:40:26:03:3f:4c"
      )
}
