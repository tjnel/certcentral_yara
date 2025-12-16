import "pe"

rule MAL_Compromised_Cert_KTCrypt_Loader_SSL_com_6524ECD66BD22BCD244151EA1C992E84 {
   meta:
      description         = "Detects KTCrypt Loader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-13"
      version             = "1.0"

      hash                = "97375c3d25d07f8e68c990a3043787f3354fb7cec1fc6be4c8a23c3abb977845"
      malware             = "KTCrypt Loader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Holy Prime Electronic Technology Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "65:24:ec:d6:6b:d2:2b:cd:24:41:51:ea:1c:99:2e:84"
      cert_thumbprint     = "825230639CA4BA809BD882668CC462A8B3A42480"
      cert_valid_from     = "2025-05-13"
      cert_valid_to       = "2026-05-12"

      country             = "CN"
      state               = "Jiangsu"
      locality            = "Wuxi"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "65:24:ec:d6:6b:d2:2b:cd:24:41:51:ea:1c:99:2e:84"
      )
}
