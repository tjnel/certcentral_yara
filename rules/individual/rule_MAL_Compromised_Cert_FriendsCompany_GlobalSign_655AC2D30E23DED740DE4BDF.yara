import "pe"

rule MAL_Compromised_Cert_FriendsCompany_GlobalSign_655AC2D30E23DED740DE4BDF {
   meta:
      description         = "Detects FriendsCompany with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-12"
      version             = "1.0"

      hash                = "a967506f4c91acb14978840b188eeacee9e8a3643340a9c89e246114f4e9c608"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Wuxi Ruisidi Precision Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "65:5a:c2:d3:0e:23:de:d7:40:de:4b:df"
      cert_thumbprint     = "BF146510C8354EF90E62724556566ABCB4085FE2"
      cert_valid_from     = "2025-02-12"
      cert_valid_to       = "2026-02-13"

      country             = "CN"
      state               = "Jiangsu"
      locality            = "Wuxi"
      email               = "???"
      rdn_serial_number   = "91320282MA266XCM5B"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "65:5a:c2:d3:0e:23:de:d7:40:de:4b:df"
      )
}
