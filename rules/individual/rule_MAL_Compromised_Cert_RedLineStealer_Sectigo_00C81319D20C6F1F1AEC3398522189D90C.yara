import "pe"

rule MAL_Compromised_Cert_RedLineStealer_Sectigo_00C81319D20C6F1F1AEC3398522189D90C {
   meta:
      description         = "Detects RedLineStealer with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-01-30"
      version             = "1.0"

      hash                = "8c98497cb266d1e0713969a64b2f3728017052d243469bfb22deb9c742ea9d9f"
      malware             = "RedLineStealer"
      malware_type        = "Infostealer"
      malware_notes       = "A malware as a service infostealer: https://www.proofpoint.com/us/blog/threat-insight/new-redline-stealer-distributed-using-coronavirus-themed-email-campaign"

      signer              = "AMCERT,LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:c8:13:19:d2:0c:6f:1f:1a:ec:33:98:52:21:89:d9:0c"
      cert_thumbprint     = "A6206300DB0CD79F5A39CA715B0F5E16A5BCBA61"
      cert_valid_from     = "2022-01-30"
      cert_valid_to       = "2023-01-30"

      country             = "AM"
      state               = "Erevan"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:c8:13:19:d2:0c:6f:1f:1a:ec:33:98:52:21:89:d9:0c"
      )
}
