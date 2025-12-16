import "pe"

rule MAL_Compromised_Cert_RemcosRAT_SSL_com_3CC9EF0DFC14DB49966F02998B6932FB {
   meta:
      description         = "Detects RemcosRAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-09"
      version             = "1.0"

      hash                = "e91506f978e3e9224e8ee589b23f1ad380cae00e40ec460970f5b0f5c6ebba8a"
      malware             = "RemcosRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SOFTWARE & MARKETING SOLUTION LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "3c:c9:ef:0d:fc:14:db:49:96:6f:02:99:8b:69:32:fb"
      cert_thumbprint     = "12F4B0D9735DC169079573BF34A898381017653A"
      cert_valid_from     = "2024-12-09"
      cert_valid_to       = "2025-12-09"

      country             = "GB"
      state               = "???"
      locality            = "Swansea"
      email               = "???"
      rdn_serial_number   = "12846100"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "3c:c9:ef:0d:fc:14:db:49:96:6f:02:99:8b:69:32:fb"
      )
}
