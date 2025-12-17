import "pe"

rule MAL_Compromised_Cert_Unknown_bootkit_SSL_com_767FCD8623FB84E3D6E7CF6F8A8078A8 {
   meta:
      description         = "Detects Unknown, bootkit? with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-12-12"
      version             = "1.0"

      hash                = "233ba2ed10b866b03a8f969e68c1c35384e6c08fe58adc5953a5f99a4f6c71db"
      malware             = "Unknown, bootkit?"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sichuan Mingchuang Sealing Technology Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "76:7f:cd:86:23:fb:84:e3:d6:e7:cf:6f:8a:80:78:a8"
      cert_thumbprint     = "7C046F80E9C41C32A7B488C9E1FA6E782425C520"
      cert_valid_from     = "2023-12-12"
      cert_valid_to       = "2024-12-11"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "???"
      rdn_serial_number   = "91510100MA62JN364R"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "76:7f:cd:86:23:fb:84:e3:d6:e7:cf:6f:8a:80:78:a8"
      )
}
