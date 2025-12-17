import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_16E03301BF83807C1755E11EAD1A8E57 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-12-01"
      version             = "1.0"

      hash                = "f2de89b2e066fd492d992f623819281e7f9d05519a8c1ed381c03444adb189e1"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Qingdao Xihongshi Technology Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "16:e0:33:01:bf:83:80:7c:17:55:e1:1e:ad:1a:8e:57"
      cert_thumbprint     = "8607290B9C29339DB24FC31EE133E5514716952E"
      cert_valid_from     = "2023-12-01"
      cert_valid_to       = "2024-11-30"

      country             = "CN"
      state               = "Shandong"
      locality            = "Qingdao"
      email               = "???"
      rdn_serial_number   = "91370202MA3Q70XK8N"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "16:e0:33:01:bf:83:80:7c:17:55:e1:1e:ad:1a:8e:57"
      )
}
