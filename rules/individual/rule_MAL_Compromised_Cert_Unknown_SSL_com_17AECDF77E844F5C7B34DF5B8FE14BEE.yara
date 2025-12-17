import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_17AECDF77E844F5C7B34DF5B8FE14BEE {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-15"
      version             = "1.0"

      hash                = "04f62ec7e2b950bb4d0f6e961264151849a6824e12319cd4343c9ca605f33537"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hebei Yibi Solidification Technology Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "17:ae:cd:f7:7e:84:4f:5c:7b:34:df:5b:8f:e1:4b:ee"
      cert_thumbprint     = "50363EFD8A97C55148C5D130D3C5E68FEBC747BA"
      cert_valid_from     = "2024-11-15"
      cert_valid_to       = "2025-11-14"

      country             = "CN"
      state               = "Hebei"
      locality            = "Baoding"
      email               = "???"
      rdn_serial_number   = "91130681MA07QJYB30"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "17:ae:cd:f7:7e:84:4f:5c:7b:34:df:5b:8f:e1:4b:ee"
      )
}
