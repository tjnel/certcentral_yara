import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_24F1C528ACBA226708DC92F692431A2C {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-26"
      version             = "1.0"

      hash                = "c1b0fe35669f425304e005f5839440356276cc20eb1cd6ceb8d0b5e6b1f96f7f"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Greenlight Softwares Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "24:f1:c5:28:ac:ba:22:67:08:dc:92:f6:92:43:1a:2c"
      cert_thumbprint     = "BC442B6500814DBC2BA2120C33409D303189AB82"
      cert_valid_from     = "2024-04-26"
      cert_valid_to       = "2025-04-26"

      country             = "GB"
      state               = "England"
      locality            = "Stanmore"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "24:f1:c5:28:ac:ba:22:67:08:dc:92:f6:92:43:1a:2c"
      )
}
