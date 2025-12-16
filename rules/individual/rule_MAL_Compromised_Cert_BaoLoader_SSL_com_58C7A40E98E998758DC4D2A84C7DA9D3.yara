import "pe"

rule MAL_Compromised_Cert_BaoLoader_SSL_com_58C7A40E98E998758DC4D2A84C7DA9D3 {
   meta:
      description         = "Detects BaoLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-05-24"
      version             = "1.0"

      hash                = "7fe1b5d86fa46d225f75c41b10420d1d4fc7ae4441a593b17a4e2a2a632e0495"
      malware             = "BaoLoader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "Interlink Media Inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "58:c7:a4:0e:98:e9:98:75:8d:c4:d2:a8:4c:7d:a9:d3"
      cert_thumbprint     = "426256085EF3583D2A4224D5275BC42D36E11CAD"
      cert_valid_from     = "2023-05-24"
      cert_valid_to       = "2026-05-23"

      country             = "PA"
      state               = "???"
      locality            = "Panama City"
      email               = "???"
      rdn_serial_number   = "155704402"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "58:c7:a4:0e:98:e9:98:75:8d:c4:d2:a8:4c:7d:a9:d3"
      )
}
