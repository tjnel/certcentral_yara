import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00C8EDCFE8BE174C2F204D858C5B91DEA5 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-12-16"
      version             = "1.0"

      hash                = "11d92a8bbd12d0f4634904ccc0037f58e99ab9d71e8341930a25564b3f2dec78"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Paarcopy Oy"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:c8:ed:cf:e8:be:17:4c:2f:20:4d:85:8c:5b:91:de:a5"
      cert_thumbprint     = "7F5F205094940793D1028960E0F0E8B654F9956E"
      cert_valid_from     = "2020-12-16"
      cert_valid_to       = "2021-12-16"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "ESPOO"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:c8:ed:cf:e8:be:17:4c:2f:20:4d:85:8c:5b:91:de:a5"
      )
}
