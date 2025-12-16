import "pe"

rule MAL_Compromised_Cert_RedLineStealer_Sectigo_00C667FFE3A5B0A5AE7CF3A9E41682E91B {
   meta:
      description         = "Detects RedLineStealer with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-29"
      version             = "1.0"

      hash                = "47ec7e0eb40aa7f939e9e83dc2eba55c0806449453bfe5a2aa603a66a094e64f"
      malware             = "RedLineStealer"
      malware_type        = "Infostealer"
      malware_notes       = "A malware as a service infostealer: https://www.proofpoint.com/us/blog/threat-insight/new-redline-stealer-distributed-using-coronavirus-themed-email-campaign"

      signer              = "NAILS UNLIMITED LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:c6:67:ff:e3:a5:b0:a5:ae:7c:f3:a9:e4:16:82:e9:1b"
      cert_thumbprint     = "6B66BA34FF01E0DAB6E68BA244D991578A69C4AD"
      cert_valid_from     = "2021-03-29"
      cert_valid_to       = "2022-03-29"

      country             = "GB"
      state               = "Dorset"
      locality            = "Dorchester"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:c6:67:ff:e3:a5:b0:a5:ae:7c:f3:a9:e4:16:82:e9:1b"
      )
}
