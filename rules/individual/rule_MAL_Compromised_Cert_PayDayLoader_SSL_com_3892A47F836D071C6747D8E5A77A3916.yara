import "pe"

rule MAL_Compromised_Cert_PayDayLoader_SSL_com_3892A47F836D071C6747D8E5A77A3916 {
   meta:
      description         = "Detects PayDayLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-09"
      version             = "1.0"

      hash                = "f82be98ea43b62e983683c0494dc6abf7a155843363f0107d484247ff1c2520a"
      malware             = "PayDayLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shanxi Jiusheng Tongyuan Renewable Energy Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "38:92:a4:7f:83:6d:07:1c:67:47:d8:e5:a7:7a:39:16"
      cert_thumbprint     = "A6550C5129DC0C2C7F7C45DCB75C9C4B9EC77666"
      cert_valid_from     = "2025-05-09"
      cert_valid_to       = "2026-05-08"

      country             = "CN"
      state               = "Shanxi"
      locality            = "Jinzhong"
      email               = "???"
      rdn_serial_number   = "91140727MA0GU6PQ3G"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "38:92:a4:7f:83:6d:07:1c:67:47:d8:e5:a7:7a:39:16"
      )
}
