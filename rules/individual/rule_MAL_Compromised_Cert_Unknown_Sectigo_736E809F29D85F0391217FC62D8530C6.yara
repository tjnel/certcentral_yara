import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_736E809F29D85F0391217FC62D8530C6 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-03-06"
      version             = "1.0"

      hash                = "1af7e7bf85eee6839a20db4c8c01c842490211e76051e65e0796726af2dbc1fd"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Zhiya Yunke (Chengdu) Finance and Tax Service Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "73:6e:80:9f:29:d8:5f:03:91:21:7f:c6:2d:85:30:c6"
      cert_thumbprint     = "08A781ABE2FFEDE9C3DD65CBDA3CB0C8F9056D04"
      cert_valid_from     = "2023-03-06"
      cert_valid_to       = "2025-03-05"

      country             = "CN"
      state               = "四川省"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "73:6e:80:9f:29:d8:5f:03:91:21:7f:c6:2d:85:30:c6"
      )
}
