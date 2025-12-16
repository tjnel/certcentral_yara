import "pe"

rule MAL_Compromised_Cert_CoinLurker_SSL_com_72B3250DD8324E027D167CB349DC57D6 {
   meta:
      description         = "Detects CoinLurker with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-02-26"
      version             = "1.0"

      hash                = "324e1bf24f13d5a8f45cc5ee25d3dfe330a7e755b19901549976f2db02ca4fa4"
      malware             = "CoinLurker"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sibur International Trading (SHANGHAI) Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "72:b3:25:0d:d8:32:4e:02:7d:16:7c:b3:49:dc:57:d6"
      cert_thumbprint     = "6C2A7731614041DB857F84FE8FEFA011AE43A187"
      cert_valid_from     = "2024-02-26"
      cert_valid_to       = "2025-02-25"

      country             = "CN"
      state               = "???"
      locality            = "Shanghai"
      email               = "???"
      rdn_serial_number   = "913101155574141123"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "72:b3:25:0d:d8:32:4e:02:7d:16:7c:b3:49:dc:57:d6"
      )
}
