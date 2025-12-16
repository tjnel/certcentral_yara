import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_590D66DBF4CFAEC528DB3CD9079A53D1 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-23"
      version             = "1.0"

      hash                = "9d6ea8cc12e0a7143cc25df1067660717c17edce99419307a34a42987fcf26e5"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Anhui PepsiCo Information Technology Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "59:0d:66:db:f4:cf:ae:c5:28:db:3c:d9:07:9a:53:d1"
      cert_thumbprint     = "7F401997FDA60D3EB3C4075E4F3201D0F0E6D11E"
      cert_valid_from     = "2025-09-23"
      cert_valid_to       = "2026-09-22"

      country             = "CN"
      state               = "Anhui"
      locality            = "Hefei"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "59:0d:66:db:f4:cf:ae:c5:28:db:3c:d9:07:9a:53:d1"
      )
}
