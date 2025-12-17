import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_2D4B965D94FBD665EDE6488405DDEC72 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-13"
      version             = "1.0"

      hash                = "5b1530a8aeb899db804464290a486a6b0235ac608c287cb89522d652fb5d571c"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shanghai Liandu Technology Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "2d:4b:96:5d:94:fb:d6:65:ed:e6:48:84:05:dd:ec:72"
      cert_thumbprint     = "CF566CFB203841F56834D2C8EB61E424AB9ADA3D"
      cert_valid_from     = "2025-06-13"
      cert_valid_to       = "2026-06-13"

      country             = "CN"
      state               = "???"
      locality            = "Shanghai"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "2d:4b:96:5d:94:fb:d6:65:ed:e6:48:84:05:dd:ec:72"
      )
}
