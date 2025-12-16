import "pe"

rule MAL_Compromised_Cert_PatchWork_SSL_com_22A068D490E1F24964C3E5BDD4055C8C {
   meta:
      description         = "Detects PatchWork with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-20"
      version             = "1.0"

      hash                = "bf9445ded122ee5853bb45d69b390ed5a0b36baa0c48adc7a8fa65e526116720"
      malware             = "PatchWork"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Nikl Design Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "22:a0:68:d4:90:e1:f2:49:64:c3:e5:bd:d4:05:5c:8c"
      cert_thumbprint     = "27E1485F9B3B7CCE0576CE74A87CE57F9F65C88C"
      cert_valid_from     = "2024-05-20"
      cert_valid_to       = "2025-05-20"

      country             = "GB"
      state               = "England"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "22:a0:68:d4:90:e1:f2:49:64:c3:e5:bd:d4:05:5c:8c"
      )
}
