import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_3094CA76D0BF4D5CA3E6F9A29C147E95 {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-09-21"
      version             = "1.0"

      hash                = "df400f2ae6ce76db40d1ed46cd648965658a2417b4b577116b89a9293ba8e385"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

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
