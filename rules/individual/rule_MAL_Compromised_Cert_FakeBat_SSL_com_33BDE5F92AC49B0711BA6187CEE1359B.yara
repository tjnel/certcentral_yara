import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_33BDE5F92AC49B0711BA6187CEE1359B {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-14"
      version             = "1.0"

      hash                = "93a005a078dc412b1e24cb5ed30639bb15ca0e8f7d7ce9a3b608b763bdbbc030"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Bloom Develop Inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "33:bd:e5:f9:2a:c4:9b:07:11:ba:61:87:ce:e1:35:9b"
      cert_thumbprint     = "D7A5FC29265E7447A27134127AA009C2C6D171B3"
      cert_valid_from     = "2024-05-14"
      cert_valid_to       = "2025-05-14"

      country             = "CA"
      state               = "Ontario"
      locality            = "Richmond Hill"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "33:bd:e5:f9:2a:c4:9b:07:11:ba:61:87:ce:e1:35:9b"
      )
}
