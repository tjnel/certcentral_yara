import "pe"

rule MAL_Compromised_Cert_HijackLoader_DigiCert_03CF154AD4C34EDBA581854D9F750F2D {
   meta:
      description         = "Detects HijackLoader with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-12-16"
      version             = "1.0"

      hash                = "26a24d3b0206c6808615c7049859c2fe62c4dcd87e7858be40ae8112b0482616"
      malware             = "HijackLoader"
      malware_type        = "Loader"
      malware_notes       = ""

      signer              = "Chengdu XiaoShanHu Information Technology Co.,Ltd."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "03:cf:15:4a:d4:c3:4e:db:a5:81:85:4d:9f:75:0f:2d"
      cert_thumbprint     = "D5758D83EC0BE571F521EBD825FBB4FE8D4C6FD6"
      cert_valid_from     = "2022-12-16"
      cert_valid_to       = "2026-01-09"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "03:cf:15:4a:d4:c3:4e:db:a5:81:85:4d:9f:75:0f:2d"
      )
}
