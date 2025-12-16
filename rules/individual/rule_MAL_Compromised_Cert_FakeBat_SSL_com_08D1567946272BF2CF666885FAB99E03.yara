import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_08D1567946272BF2CF666885FAB99E03 {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-12-20"
      version             = "1.0"

      hash                = "eb986a5ea4c7068fadcecc429c133fd501215d422448f95c9b7b1cf158b2f8a6"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Rapport Creative Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "08:d1:56:79:46:27:2b:f2:cf:66:68:85:fa:b9:9e:03"
      cert_thumbprint     = "44A3056EE75B31799D9C74B1956AA3038FA63785"
      cert_valid_from     = "2023-12-20"
      cert_valid_to       = "2024-12-19"

      country             = "GB"
      state               = "???"
      locality            = "Luton"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "08:d1:56:79:46:27:2b:f2:cf:66:68:85:fa:b9:9e:03"
      )
}
