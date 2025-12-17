import "pe"

rule MAL_Compromised_Cert_SYSTEMBC_SSL_com_23D2CAAE31B75460ACDBD1B42D6E7743 {
   meta:
      description         = "Detects SYSTEMBC with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-15"
      version             = "1.0"

      hash                = "24b6ddd3028c28d0a13da0354333d19cbc8fd12d4351f083c8cb3a93ec3ae793"
      malware             = "SYSTEMBC"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Guizhou Qi'ang Kangyuan Rosa Roxburghii Development Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "23:d2:ca:ae:31:b7:54:60:ac:db:d1:b4:2d:6e:77:43"
      cert_thumbprint     = "B55DAD8DA97FA6AF0272102ED0E55E76E753FD04"
      cert_valid_from     = "2024-06-15"
      cert_valid_to       = "2025-06-14"

      country             = "CN"
      state               = "Guizhou"
      locality            = "Qiannan Buyi and Miao Autonomous Prefecture"
      email               = "???"
      rdn_serial_number   = "91522730MA6DJY9R40"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "23:d2:ca:ae:31:b7:54:60:ac:db:d1:b4:2d:6e:77:43"
      )
}
