import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_1DEEA179F5757FE529043577762419DF {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-02-21"
      version             = "1.0"

      hash                = "07c6b6453907697a5832f5ef5b99dda2180b9f5fd4fee7ba8f64bab637db8fb1"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "SPIRIT CONSULTING s. r. o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "1d:ee:a1:79:f5:75:7f:e5:29:04:35:77:76:24:19:df"
      cert_thumbprint     = "FFEED7E7C8E52BE64DC7DDFEFF2B1FB257607EF2"
      cert_valid_from     = "2022-02-21"
      cert_valid_to       = "2023-02-21"

      country             = "SK"
      state               = "Trnavský kraj"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "1d:ee:a1:79:f5:75:7f:e5:29:04:35:77:76:24:19:df"
      )
}
