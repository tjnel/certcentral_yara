import "pe"

rule MAL_Compromised_Cert_WarmCookie_SSL_com_7AD3A37E018A0708865FBA3EF5EFC572 {
   meta:
      description         = "Detects WarmCookie with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-28"
      version             = "1.0"

      hash                = "f75158de839346c9a029d30fb806cb6b4cefa12cd2eb2fe6b58703e91261c27a"
      malware             = "WarmCookie"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DEVELOPMENT CORPORATE CONSULTANCY LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "7a:d3:a3:7e:01:8a:07:08:86:5f:ba:3e:f5:ef:c5:72"
      cert_thumbprint     = "E3A6E0E07B935F225C45E01CCE97F38EC6D80DC7"
      cert_valid_from     = "2024-11-28"
      cert_valid_to       = "2025-11-28"

      country             = "GB"
      state               = "???"
      locality            = "Bath"
      email               = "???"
      rdn_serial_number   = "10672092"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "7a:d3:a3:7e:01:8a:07:08:86:5f:ba:3e:f5:ef:c5:72"
      )
}
