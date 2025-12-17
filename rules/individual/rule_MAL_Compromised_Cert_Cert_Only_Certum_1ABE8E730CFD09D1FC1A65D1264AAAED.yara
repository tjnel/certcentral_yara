import "pe"

rule MAL_Compromised_Cert_Cert_Only_Certum_1ABE8E730CFD09D1FC1A65D1264AAAED {
   meta:
      description         = "Detects Cert Only with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-02"
      version             = "1.0"

      hash                = "290f24edceb8eddf98e89ed3a1a8e823ab052563baa015308a6696c0d3ce79e3"
      malware             = "Cert Only"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shenzhen Xinshitong Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "1a:be:8e:73:0c:fd:09:d1:fc:1a:65:d1:26:4a:aa:ed"
      cert_thumbprint     = "8F44A139359DDB9310C681526C560F207B706115"
      cert_valid_from     = "2024-10-02"
      cert_valid_to       = "2025-10-02"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Shenzhen"
      email               = "???"
      rdn_serial_number   = "914403003426869970"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "1a:be:8e:73:0c:fd:09:d1:fc:1a:65:d1:26:4a:aa:ed"
      )
}
