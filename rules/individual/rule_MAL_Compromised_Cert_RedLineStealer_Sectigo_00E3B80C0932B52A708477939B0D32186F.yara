import "pe"

rule MAL_Compromised_Cert_RedLineStealer_Sectigo_00E3B80C0932B52A708477939B0D32186F {
   meta:
      description         = "Detects RedLineStealer with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-30"
      version             = "1.0"

      hash                = "619f3111ecda81c05a1caa5d84be3bd13afd54439610738637615da53418922a"
      malware             = "RedLineStealer"
      malware_type        = "Infostealer"
      malware_notes       = "A malware as a service infostealer: https://www.proofpoint.com/us/blog/threat-insight/new-redline-stealer-distributed-using-coronavirus-themed-email-campaign"

      signer              = "BISOYETUTU LTD LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:e3:b8:0c:09:32:b5:2a:70:84:77:93:9b:0d:32:18:6f"
      cert_thumbprint     = "1D2B5D4F0DE1D7CE4ABF82FDC58ADC43BC28ADEE"
      cert_valid_from     = "2021-03-30"
      cert_valid_to       = "2022-03-30"

      country             = "GB"
      state               = "West Midlands"
      locality            = "Coventry"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:e3:b8:0c:09:32:b5:2a:70:84:77:93:9b:0d:32:18:6f"
      )
}
