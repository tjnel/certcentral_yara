import "pe"

rule MAL_Compromised_Cert_RedLineStealer_Sectigo_00E0A83917660D05CF476374659D3C7B85 {
   meta:
      description         = "Detects RedLineStealer with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-05-20"
      version             = "1.0"

      hash                = "7f5fb937bb138c7e292ec64f79ac0b6d887d47a8b3e21153c1a05df91dfb823b"
      malware             = "RedLineStealer"
      malware_type        = "Infostealer"
      malware_notes       = "A malware as a service infostealer: https://www.proofpoint.com/us/blog/threat-insight/new-redline-stealer-distributed-using-coronavirus-themed-email-campaign"

      signer              = "PIK MOTEL S.R.L."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:e0:a8:39:17:66:0d:05:cf:47:63:74:65:9d:3c:7b:85"
      cert_thumbprint     = "E997177ABB8C6A01A9D5B2E9578E9F7E9C6E6576"
      cert_valid_from     = "2021-05-20"
      cert_valid_to       = "2022-05-20"

      country             = "RO"
      state               = "Prahova"
      locality            = "Negoiesti"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:e0:a8:39:17:66:0d:05:cf:47:63:74:65:9d:3c:7b:85"
      )
}
