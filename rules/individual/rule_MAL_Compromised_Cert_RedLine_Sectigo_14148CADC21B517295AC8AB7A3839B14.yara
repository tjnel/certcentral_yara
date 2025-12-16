import "pe"

rule MAL_Compromised_Cert_RedLine_Sectigo_14148CADC21B517295AC8AB7A3839B14 {
   meta:
      description         = "Detects RedLine with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-02-26"
      version             = "1.0"

      hash                = "95d977f2a9f6db1776ed9bbd124f0e3ce58bf84031f92816de02bc5593bb6c33"
      malware             = "RedLine"
      malware_type        = "Infostealer"
      malware_notes       = "A malware as a service infostealer: https://www.proofpoint.com/us/blog/threat-insight/new-redline-stealer-distributed-using-coronavirus-themed-email-campaign"

      signer              = "AHMADI MOHAMMAD ZAHER"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA E36"
      cert_serial         = "14:14:8c:ad:c2:1b:51:72:95:ac:8a:b7:a3:83:9b:14"
      cert_thumbprint     = "788CD9D9A54B675BF594F2EB393A8533D198E210"
      cert_valid_from     = "2024-02-26"
      cert_valid_to       = "2025-02-25"

      country             = "US"
      state               = "Texas"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA E36" and
         sig.serial == "14:14:8c:ad:c2:1b:51:72:95:ac:8a:b7:a3:83:9b:14"
      )
}
