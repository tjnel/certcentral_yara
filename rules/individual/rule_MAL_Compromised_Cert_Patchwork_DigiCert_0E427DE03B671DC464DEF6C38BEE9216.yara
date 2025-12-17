import "pe"

rule MAL_Compromised_Cert_Patchwork_DigiCert_0E427DE03B671DC464DEF6C38BEE9216 {
   meta:
      description         = "Detects Patchwork with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-08-16"
      version             = "1.0"

      hash                = "622e1b6677c32ff0b83f08a2c1f4a7384dbe8e7075f6c5917dd3419df1311631"
      malware             = "Patchwork"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shanghai Baizhi Network Technology Co., Ltd."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0e:42:7d:e0:3b:67:1d:c4:64:de:f6:c3:8b:ee:92:16"
      cert_thumbprint     = "4D875FFF62AFEAC46BD847CC710F5B5C8D1333A8"
      cert_valid_from     = "2023-08-16"
      cert_valid_to       = "2026-08-15"

      country             = "CN"
      state               = "上海市"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91310114MA1GWA6R46"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0e:42:7d:e0:3b:67:1d:c4:64:de:f6:c3:8b:ee:92:16"
      )
}
