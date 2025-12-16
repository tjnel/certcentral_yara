import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_2C1EE9B583310B5E34A1EE6945A34B26 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-12-10"
      version             = "1.0"

      hash                = "71e2483b2d36765651132c9c1f935784a2008a91159b0ee3bbfb94193d0d644e"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "OOO Artmarket"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "2c:1e:e9:b5:83:31:0b:5e:34:a1:ee:69:45:a3:4b:26"
      cert_thumbprint     = "C5F078E8476D5FCFE35F67719BF6E7CAF9F85F61"
      cert_valid_from     = "2020-12-10"
      cert_valid_to       = "2021-12-10"

      country             = "RU"
      state               = "???"
      locality            = "Ekaterinburg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "2c:1e:e9:b5:83:31:0b:5e:34:a1:ee:69:45:a3:4b:26"
      )
}
