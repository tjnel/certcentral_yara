import "pe"

rule MAL_Compromised_Cert_Mofongoloader_Sectigo_6AB35C5785260695E9C012514DB0C299 {
   meta:
      description         = "Detects Mofongoloader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-05-15"
      version             = "1.0"

      hash                = "b68adceb4eea31a7f1ad264b3fbff20526bb96049ceb41f43310c46bc543d4a5"
      malware             = "Mofongoloader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "GreenEngine OU"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "6a:b3:5c:57:85:26:06:95:e9:c0:12:51:4d:b0:c2:99"
      cert_thumbprint     = "69B1966E16949B9C76A66C82EB077109F764EBA2"
      cert_valid_from     = "2023-05-15"
      cert_valid_to       = "2024-05-14"

      country             = "EE"
      state               = "Harjumaa"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "6a:b3:5c:57:85:26:06:95:e9:c0:12:51:4d:b0:c2:99"
      )
}
