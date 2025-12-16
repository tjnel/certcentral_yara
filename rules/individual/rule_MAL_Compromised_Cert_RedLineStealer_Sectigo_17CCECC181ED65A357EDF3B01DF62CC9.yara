import "pe"

rule MAL_Compromised_Cert_RedLineStealer_Sectigo_17CCECC181ED65A357EDF3B01DF62CC9 {
   meta:
      description         = "Detects RedLineStealer with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-03-24"
      version             = "1.0"

      hash                = "2fc13abe0d83b451a7a7fb55630c629a8b2d0b3197e66204434fd7ce52f5162c"
      malware             = "RedLineStealer"
      malware_type        = "Infostealer"
      malware_notes       = "A malware as a service infostealer: https://www.proofpoint.com/us/blog/threat-insight/new-redline-stealer-distributed-using-coronavirus-themed-email-campaign"

      signer              = "AMCERT,LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "17:cc:ec:c1:81:ed:65:a3:57:ed:f3:b0:1d:f6:2c:c9"
      cert_thumbprint     = "993C2D2CF1522ECBEE99215487EDEB6085D09931"
      cert_valid_from     = "2022-03-24"
      cert_valid_to       = "2023-03-24"

      country             = "AM"
      state               = "Erevan"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "17:cc:ec:c1:81:ed:65:a3:57:ed:f3:b0:1d:f6:2c:c9"
      )
}
