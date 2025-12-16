import "pe"

rule MAL_Compromised_Cert_FakeBat_Certificate_SSL_com_6F243A754279474D61BC06CA813DC62F {
   meta:
      description         = "Detects FakeBat_Certificate with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-30"
      version             = "1.0"

      hash                = "1af98d338a6193914a73a656797d05803b968cee3048176a30abe5b77b1b2362"
      malware             = "FakeBat_Certificate"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Xalibu Consultation Inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "6f:24:3a:75:42:79:47:4d:61:bc:06:ca:81:3d:c6:2f"
      cert_thumbprint     = "1DD356A251076D5F1AFEC33531A00F659A025037"
      cert_valid_from     = "2024-05-30"
      cert_valid_to       = "2025-05-30"

      country             = "CA"
      state               = "Quebec"
      locality            = "Saint-Lambert"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "6f:24:3a:75:42:79:47:4d:61:bc:06:ca:81:3d:c6:2f"
      )
}
