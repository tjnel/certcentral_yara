import "pe"

rule MAL_Compromised_Cert_RedLineStealer_Sectigo_4659FA5FC1E0397DF79FD6A4083D93B0 {
   meta:
      description         = "Detects RedLineStealer with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-02-28"
      version             = "1.0"

      hash                = "10240e8eafe3db72419c91f5344f2bc414e79c199153b5b6a1bd753788d6fd4d"
      malware             = "RedLineStealer"
      malware_type        = "Infostealer"
      malware_notes       = "A malware as a service infostealer: https://www.proofpoint.com/us/blog/threat-insight/new-redline-stealer-distributed-using-coronavirus-themed-email-campaign"

      signer              = "Incuber Services LLP"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "46:59:fa:5f:c1:e0:39:7d:f7:9f:d6:a4:08:3d:93:b0"
      cert_thumbprint     = "7445BDC877315ED36FB18A4FD0F345DC29FEEAAD"
      cert_valid_from     = "2023-02-28"
      cert_valid_to       = "2024-02-28"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "46:59:fa:5f:c1:e0:39:7d:f7:9f:d6:a4:08:3d:93:b0"
      )
}
