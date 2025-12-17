import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00B61B8E71514059ADC604DA05C283E514 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-10-22"
      version             = "1.0"

      hash                = "12a59869c0e78eed60e76adc9c592ba8b9f3d2835f19d4c46e7a458739d6aedf"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "APP DIVISION ApS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:b6:1b:8e:71:51:40:59:ad:c6:04:da:05:c2:83:e5:14"
      cert_thumbprint     = "67EE69F380CA62B28CECFBEF406970DDD26CD9BE"
      cert_valid_from     = "2020-10-22"
      cert_valid_to       = "2021-10-22"

      country             = "DK"
      state               = "Syddanmark"
      locality            = "Årslev"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:b6:1b:8e:71:51:40:59:ad:c6:04:da:05:c2:83:e5:14"
      )
}
