import "pe"

rule MAL_Compromised_Cert_RaccoonStealer_Sectigo_00B0A308FC2E71AC4AC40677B9C27CCBAD {
   meta:
      description         = "Detects RaccoonStealer with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-01-27"
      version             = "1.0"

      hash                = "18f6edcc25f8528d841203138beedaee611f3b3d17fbc5e13be8fd744ca413ed"
      malware             = "RaccoonStealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Volpayk LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:b0:a3:08:fc:2e:71:ac:4a:c4:06:77:b9:c2:7c:cb:ad"
      cert_thumbprint     = "15E502F1482A280F7285168BB5E227FFDE4E41A6"
      cert_valid_from     = "2021-01-27"
      cert_valid_to       = "2022-01-27"

      country             = "RU"
      state               = "???"
      locality            = "Saint-Petersburg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:b0:a3:08:fc:2e:71:ac:4a:c4:06:77:b9:c2:7c:cb:ad"
      )
}
