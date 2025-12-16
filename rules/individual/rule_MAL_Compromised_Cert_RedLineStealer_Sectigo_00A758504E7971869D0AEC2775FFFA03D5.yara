import "pe"

rule MAL_Compromised_Cert_RedLineStealer_Sectigo_00A758504E7971869D0AEC2775FFFA03D5 {
   meta:
      description         = "Detects RedLineStealer with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-06-14"
      version             = "1.0"

      hash                = "ba313b84b44bb158c77aacd4fc959014ac5d3af815da80938937168f2305b85f"
      malware             = "RedLineStealer"
      malware_type        = "Infostealer"
      malware_notes       = "A malware as a service infostealer: https://www.proofpoint.com/us/blog/threat-insight/new-redline-stealer-distributed-using-coronavirus-themed-email-campaign"

      signer              = "Amcert LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:a7:58:50:4e:79:71:86:9d:0a:ec:27:75:ff:fa:03:d5"
      cert_thumbprint     = "646BBB3A37CC004BEA6EFCD48579D1A5776CB157"
      cert_valid_from     = "2021-06-14"
      cert_valid_to       = "2022-06-14"

      country             = "AM"
      state               = "???"
      locality            = "Yerevan"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:a7:58:50:4e:79:71:86:9d:0a:ec:27:75:ff:fa:03:d5"
      )
}
