import "pe"

rule MAL_Compromised_Cert_RoningLoader_Certum_12260D4CCD0095A20C7042FE011E65C2 {
   meta:
      description         = "Detects RoningLoader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-03"
      version             = "1.0"

      hash                = "2515b546125d20013237aeadec5873e6438ada611347035358059a77a32c54f5"
      malware             = "RoningLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Kunming Wuqi E-commerce Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "12:26:0d:4c:cd:00:95:a2:0c:70:42:fe:01:1e:65:c2"
      cert_thumbprint     = "3E5F2C4C90F5283F35568CE15B0F1DBAF1FE146D"
      cert_valid_from     = "2025-02-03"
      cert_valid_to       = "2026-02-03"

      country             = "CN"
      state               = "Hubei"
      locality            = "Xiangfan"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "12:26:0d:4c:cd:00:95:a2:0c:70:42:fe:01:1e:65:c2"
      )
}
