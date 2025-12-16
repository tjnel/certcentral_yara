import "pe"

rule MAL_Compromised_Cert_CrazyEvilTraffer_GlobalSign_1FBFB66ADE0146F9C61C6218 {
   meta:
      description         = "Detects CrazyEvilTraffer with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-25"
      version             = "1.0"

      hash                = "4a802433176d4678103090719cd052db50692b2755945e57717f28e5dc257b3d"
      malware             = "CrazyEvilTraffer"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Heze Hongwei Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "1f:bf:b6:6a:de:01:46:f9:c6:1c:62:18"
      cert_thumbprint     = "88BF2C043ACE8CBC5211B5ED99DBDF9C2F24FF20"
      cert_valid_from     = "2025-06-25"
      cert_valid_to       = "2026-06-26"

      country             = "CN"
      state               = "Shandong"
      locality            = "Heze"
      email               = "???"
      rdn_serial_number   = "91371702MABYMG6429"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "1f:bf:b6:6a:de:01:46:f9:c6:1c:62:18"
      )
}
