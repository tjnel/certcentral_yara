import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00E5AD42C509A7C24605530D35832C091E {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-09-04"
      version             = "1.0"

      hash                = "3849944c5db10f13305f76c92c1a8c80bc37f6a0514c19ea4a2bbeae62438113"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "VESNA, OOO"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:e5:ad:42:c5:09:a7:c2:46:05:53:0d:35:83:2c:09:1e"
      cert_thumbprint     = "64197FF3B465B9D3C9300EB985CE635EE1C3DD6A"
      cert_valid_from     = "2020-09-04"
      cert_valid_to       = "2021-09-04"

      country             = "RU"
      state               = "???"
      locality            = "Saint Petersburg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:e5:ad:42:c5:09:a7:c2:46:05:53:0d:35:83:2c:09:1e"
      )
}
