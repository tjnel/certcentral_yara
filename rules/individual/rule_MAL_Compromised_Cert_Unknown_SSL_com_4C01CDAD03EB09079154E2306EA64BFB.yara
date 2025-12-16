import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_4C01CDAD03EB09079154E2306EA64BFB {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-18"
      version             = "1.0"

      hash                = "dcc64a3e8791dc7d343a656a67f0f9ff600ef5998f3730094a284b447cc43709"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shanghai Liuran Trading Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "4c:01:cd:ad:03:eb:09:07:91:54:e2:30:6e:a6:4b:fb"
      cert_thumbprint     = "99F9E9B0AF0D8398C4FD6C52A4F8EFEDB5761853"
      cert_valid_from     = "2024-08-18"
      cert_valid_to       = "2025-08-18"

      country             = "CN"
      state               = "???"
      locality            = "Shanghai"
      email               = "???"
      rdn_serial_number   = "913100005559922937"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "4c:01:cd:ad:03:eb:09:07:91:54:e2:30:6e:a6:4b:fb"
      )
}
