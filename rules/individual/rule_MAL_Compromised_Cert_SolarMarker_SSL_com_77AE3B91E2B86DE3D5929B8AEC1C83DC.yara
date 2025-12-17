import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_77AE3B91E2B86DE3D5929B8AEC1C83DC {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-09-19"
      version             = "1.0"

      hash                = "820eda2078723e7f1c09d0e6d3641ea822c2b36c981cb5bfa4e445733664c087"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "ТОВ \"Софт Енжін юа\""
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "77:ae:3b:91:e2:b8:6d:e3:d5:92:9b:8a:ec:1c:83:dc"
      cert_thumbprint     = "592FCE66E13CEAAB64900F31278D9332B2F2C007"
      cert_valid_from     = "2023-09-19"
      cert_valid_to       = "2024-09-18"

      country             = "UA"
      state               = "Zhytomyr Oblast"
      locality            = "Zhytomyr"
      email               = "???"
      rdn_serial_number   = "45310779"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "77:ae:3b:91:e2:b8:6d:e3:d5:92:9b:8a:ec:1c:83:dc"
      )
}
