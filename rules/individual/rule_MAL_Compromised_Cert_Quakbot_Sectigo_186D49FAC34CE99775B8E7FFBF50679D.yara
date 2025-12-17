import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_186D49FAC34CE99775B8E7FFBF50679D {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-10-09"
      version             = "1.0"

      hash                = "aadef6b90d90f628926fe3ca9bcc2104430bc404e9e451282ae139bcbde43320"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Hairis LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "18:6d:49:fa:c3:4c:e9:97:75:b8:e7:ff:bf:50:67:9d"
      cert_thumbprint     = "9E6B37CB10C99057177F2FED41E1068149A3BF40"
      cert_valid_from     = "2020-10-09"
      cert_valid_to       = "2021-10-09"

      country             = "RU"
      state               = "???"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "18:6d:49:fa:c3:4c:e9:97:75:b8:e7:ff:bf:50:67:9d"
      )
}
