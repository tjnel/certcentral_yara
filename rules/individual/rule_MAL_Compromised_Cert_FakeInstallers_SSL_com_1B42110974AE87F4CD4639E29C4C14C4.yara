import "pe"

rule MAL_Compromised_Cert_FakeInstallers_SSL_com_1B42110974AE87F4CD4639E29C4C14C4 {
   meta:
      description         = "Detects FakeInstallers with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-01"
      version             = "1.0"

      hash                = "45e50aaff3991801924650d05d84750ae94f0900c6238eaed4fc79fd2fb9cdc3"
      malware             = "FakeInstallers"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ESPRESSO EDUTECH DIGI PRIVATE LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "1b:42:11:09:74:ae:87:f4:cd:46:39:e2:9c:4c:14:c4"
      cert_thumbprint     = "2F9FAEA49C640DB8F4D22D01C1D85D62AB5F50F8"
      cert_valid_from     = "2025-09-01"
      cert_valid_to       = "2026-09-01"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Kota"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "1b:42:11:09:74:ae:87:f4:cd:46:39:e2:9c:4c:14:c4"
      )
}
