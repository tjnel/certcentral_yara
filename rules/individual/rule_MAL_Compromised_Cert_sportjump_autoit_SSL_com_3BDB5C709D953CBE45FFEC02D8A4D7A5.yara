import "pe"

rule MAL_Compromised_Cert_sportjump_autoit_SSL_com_3BDB5C709D953CBE45FFEC02D8A4D7A5 {
   meta:
      description         = "Detects sportjump_autoit with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-03-28"
      version             = "1.0"

      hash                = "5e152be0bec7debd19c26c4daa67e16a8c037b1c0fa112dc13e151037c84a985"
      malware             = "sportjump_autoit"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Dupa Innovation Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "3b:db:5c:70:9d:95:3c:be:45:ff:ec:02:d8:a4:d7:a5"
      cert_thumbprint     = "52977AEDE5D3054EEEAB2CD53B08E5E920C84217"
      cert_valid_from     = "2024-03-28"
      cert_valid_to       = "2025-03-28"

      country             = "GB"
      state               = "Wales"
      locality            = "Penarth"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "3b:db:5c:70:9d:95:3c:be:45:ff:ec:02:d8:a4:d7:a5"
      )
}
