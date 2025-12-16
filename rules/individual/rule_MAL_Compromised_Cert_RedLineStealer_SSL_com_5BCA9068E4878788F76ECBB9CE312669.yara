import "pe"

rule MAL_Compromised_Cert_RedLineStealer_SSL_com_5BCA9068E4878788F76ECBB9CE312669 {
   meta:
      description         = "Detects RedLineStealer with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-26"
      version             = "1.0"

      hash                = "db8d4cc2d61f71408623dc1aa242d874c754a6ba51e53b2514888016a0444fe0"
      malware             = "RedLineStealer"
      malware_type        = "Infostealer"
      malware_notes       = "A malware as a service infostealer: https://www.proofpoint.com/us/blog/threat-insight/new-redline-stealer-distributed-using-coronavirus-themed-email-campaign"

      signer              = "Ranwell Creative Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "5b:ca:90:68:e4:87:87:88:f7:6e:cb:b9:ce:31:26:69"
      cert_thumbprint     = "2FE2725217483111DB53167C53657AA0FAAD5DEE"
      cert_valid_from     = "2024-01-26"
      cert_valid_to       = "2025-01-24"

      country             = "GB"
      state               = "???"
      locality            = "Little Rissington"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "5b:ca:90:68:e4:87:87:88:f7:6e:cb:b9:ce:31:26:69"
      )
}
