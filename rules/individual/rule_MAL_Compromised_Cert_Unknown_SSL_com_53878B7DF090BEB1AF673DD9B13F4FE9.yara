import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_53878B7DF090BEB1AF673DD9B13F4FE9 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-26"
      version             = "1.0"

      hash                = "5705ba9c6c35cc9b6cfec8de204ce5e749a7794463705587015b682460e7f4e3"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shanghai Ruiyi Supply Chain Management Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "53:87:8b:7d:f0:90:be:b1:af:67:3d:d9:b1:3f:4f:e9"
      cert_thumbprint     = "5DED849D4FC58BFF553CFED17DE1944927F668F5"
      cert_valid_from     = "2024-11-26"
      cert_valid_to       = "2025-11-25"

      country             = "CN"
      state               = "???"
      locality            = "Shanghai"
      email               = "???"
      rdn_serial_number   = "91310113MA1GK3AX4A"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "53:87:8b:7d:f0:90:be:b1:af:67:3d:d9:b1:3f:4f:e9"
      )
}
