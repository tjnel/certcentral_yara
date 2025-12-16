import "pe"

rule MAL_Compromised_Cert_RedLineStealer_Sectigo_282A8A04073ECED658B9770BDA8C0D28 {
   meta:
      description         = "Detects RedLineStealer with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-07-22"
      version             = "1.0"

      hash                = "45fff4489cc037313de8edf3589515197c184579658921fb06eb6fd4e860253e"
      malware             = "RedLineStealer"
      malware_type        = "Infostealer"
      malware_notes       = "A malware as a service infostealer: https://www.proofpoint.com/us/blog/threat-insight/new-redline-stealer-distributed-using-coronavirus-themed-email-campaign"

      signer              = "OOO Betamaynd"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "28:2a:8a:04:07:3e:ce:d6:58:b9:77:0b:da:8c:0d:28"
      cert_thumbprint     = "6F3224C70658F915B4EA29E80EE9633CBE48D795"
      cert_valid_from     = "2021-07-22"
      cert_valid_to       = "2022-07-22"

      country             = "RU"
      state               = "???"
      locality            = "Saint-Petersburg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "28:2a:8a:04:07:3e:ce:d6:58:b9:77:0b:da:8c:0d:28"
      )
}
