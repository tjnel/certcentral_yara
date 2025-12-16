import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_3094CA76D0BF4D5CA3E6F9A29C147E95 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-09-21"
      version             = "1.0"

      hash                = "5aac2fb148ad8ac3bf47840161acf0d111ff6898a06e2e3d2f2d544a373570c2"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Futurity Designs Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "30:94:ca:76:d0:bf:4d:5c:a3:e6:f9:a2:9c:14:7e:95"
      cert_thumbprint     = "D30FAAE824902AB96EA412D28B7D2058E0A607FD"
      cert_valid_from     = "2023-09-21"
      cert_valid_to       = "2024-09-20"

      country             = "GB"
      state               = "???"
      locality            = "Somerton"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "30:94:ca:76:d0:bf:4d:5c:a3:e6:f9:a2:9c:14:7e:95"
      )
}
