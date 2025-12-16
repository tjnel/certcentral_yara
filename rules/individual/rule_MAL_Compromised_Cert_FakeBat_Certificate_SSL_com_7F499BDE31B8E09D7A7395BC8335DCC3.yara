import "pe"

rule MAL_Compromised_Cert_FakeBat_Certificate_SSL_com_7F499BDE31B8E09D7A7395BC8335DCC3 {
   meta:
      description         = "Detects FakeBat_Certificate with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-17"
      version             = "1.0"

      hash                = "ef5870488f255bf29b3c25cfa010e543119f2cf417eed6ada09d7e40b69dd52e"
      malware             = "FakeBat_Certificate"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Creative Bees Inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "7f:49:9b:de:31:b8:e0:9d:7a:73:95:bc:83:35:dc:c3"
      cert_thumbprint     = "DA677B43EA753A482835C11337DE2F223CE16C18"
      cert_valid_from     = "2024-05-17"
      cert_valid_to       = "2025-05-17"

      country             = "CA"
      state               = "Ontario"
      locality            = "Maple"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "7f:49:9b:de:31:b8:e0:9d:7a:73:95:bc:83:35:dc:c3"
      )
}
