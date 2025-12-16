import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_6BEDCE92A6154B7E7E52ECE2FC8D0CC3 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-09-18"
      version             = "1.0"

      hash                = "2deeeda412c40ad515dca940916a376d187219ed09ed697b4be4879b7091ec53"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ekb Path Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "6b:ed:ce:92:a6:15:4b:7e:7e:52:ec:e2:fc:8d:0c:c3"
      cert_thumbprint     = "9F7ADD6E169A09F23FE289D2CD1759AAB4C5FA9C"
      cert_valid_from     = "2023-09-18"
      cert_valid_to       = "2024-09-17"

      country             = "GB"
      state               = "???"
      locality            = "Northampton"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "6b:ed:ce:92:a6:15:4b:7e:7e:52:ec:e2:fc:8d:0c:c3"
      )
}
