import "pe"

rule MAL_Compromised_Cert_RedLineStealer_Sectigo_634E16E38F12E9A71ACA08E4C6B2DBB9 {
   meta:
      description         = "Detects RedLineStealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-19"
      version             = "1.0"

      hash                = "e95d92772e18190dbde834744c74aa2ab7fda3b01e1ca839fabb8a4285b4e148"
      malware             = "RedLineStealer"
      malware_type        = "Infostealer"
      malware_notes       = "A malware as a service infostealer: https://www.proofpoint.com/us/blog/threat-insight/new-redline-stealer-distributed-using-coronavirus-themed-email-campaign"

      signer              = "AUTO RESPONSE LTD CYF"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "63:4e:16:e3:8f:12:e9:a7:1a:ca:08:e4:c6:b2:db:b9"
      cert_thumbprint     = "93A416ECF173B744C3C0E5E45C8FB23BF01FA387"
      cert_valid_from     = "2021-03-19"
      cert_valid_to       = "2022-03-19"

      country             = "GB"
      state               = "???"
      locality            = "Cardiff"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "63:4e:16:e3:8f:12:e9:a7:1a:ca:08:e4:c6:b2:db:b9"
      )
}
