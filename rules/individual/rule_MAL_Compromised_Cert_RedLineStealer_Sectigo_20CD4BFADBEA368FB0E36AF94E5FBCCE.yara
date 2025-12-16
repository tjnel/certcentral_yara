import "pe"

rule MAL_Compromised_Cert_RedLineStealer_Sectigo_20CD4BFADBEA368FB0E36AF94E5FBCCE {
   meta:
      description         = "Detects RedLineStealer with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-11-19"
      version             = "1.0"

      hash                = "3d05fee7a89dfce1ad029562fa7b84346bce12d932214cde9b26f266d53ce49c"
      malware             = "RedLineStealer"
      malware_type        = "Infostealer"
      malware_notes       = "A malware as a service infostealer: https://www.proofpoint.com/us/blog/threat-insight/new-redline-stealer-distributed-using-coronavirus-themed-email-campaign"

      signer              = "FESTAP s.r.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "20:cd:4b:fa:db:ea:36:8f:b0:e3:6a:f9:4e:5f:bc:ce"
      cert_thumbprint     = "9FC1B14D7BE09D11034B550D7FEA246ACFD3C490"
      cert_valid_from     = "2020-11-19"
      cert_valid_to       = "2021-11-19"

      country             = "SK"
      state               = "???"
      locality            = "Bratislava"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "20:cd:4b:fa:db:ea:36:8f:b0:e3:6a:f9:4e:5f:bc:ce"
      )
}
