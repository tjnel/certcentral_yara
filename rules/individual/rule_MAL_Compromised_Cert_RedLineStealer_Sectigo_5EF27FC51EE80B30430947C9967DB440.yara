import "pe"

rule MAL_Compromised_Cert_RedLineStealer_Sectigo_5EF27FC51EE80B30430947C9967DB440 {
   meta:
      description         = "Detects RedLineStealer with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-11-30"
      version             = "1.0"

      hash                = "79b98dc1721e0714219f12fcd5683d532c49ec6147a2e8b1efe94edc7148f839"
      malware             = "RedLineStealer"
      malware_type        = "Infostealer"
      malware_notes       = "A malware as a service infostealer: https://www.proofpoint.com/us/blog/threat-insight/new-redline-stealer-distributed-using-coronavirus-themed-email-campaign"

      signer              = "AMCERT,LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "5e:f2:7f:c5:1e:e8:0b:30:43:09:47:c9:96:7d:b4:40"
      cert_thumbprint     = "9232B1D2BC069AEE6194B24C73117DF993BFB7A5"
      cert_valid_from     = "2021-11-30"
      cert_valid_to       = "2022-11-30"

      country             = "AM"
      state               = "Erevan"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "5e:f2:7f:c5:1e:e8:0b:30:43:09:47:c9:96:7d:b4:40"
      )
}
