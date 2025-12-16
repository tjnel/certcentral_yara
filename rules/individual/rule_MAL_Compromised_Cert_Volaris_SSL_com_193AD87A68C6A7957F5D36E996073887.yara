import "pe"

rule MAL_Compromised_Cert_Volaris_SSL_com_193AD87A68C6A7957F5D36E996073887 {
   meta:
      description         = "Detects Volaris with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-22"
      version             = "1.0"

      hash                = "67aa59b0e9cee6279e2ebe9d18a11574d18dd195a86d24f2b87b1824c390f2b5"
      malware             = "Volaris"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CAPELLO MEDIA SOLUTIONS LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "19:3a:d8:7a:68:c6:a7:95:7f:5d:36:e9:96:07:38:87"
      cert_thumbprint     = "5ABD272A417A6DF253685679C4DCDB3A4CB24A4D"
      cert_valid_from     = "2025-07-22"
      cert_valid_to       = "2026-06-30"

      country             = "GB"
      state               = "???"
      locality            = "ALTRINCHAM"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "19:3a:d8:7a:68:c6:a7:95:7f:5d:36:e9:96:07:38:87"
      )
}
