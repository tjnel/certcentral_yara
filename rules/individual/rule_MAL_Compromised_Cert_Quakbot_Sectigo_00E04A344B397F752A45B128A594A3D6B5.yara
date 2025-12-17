import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00E04A344B397F752A45B128A594A3D6B5 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-08-18"
      version             = "1.0"

      hash                = "fa70becac90d59aa490f4735e317fe5950b3e05dd6537894a38608413369d649"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Highweb Ireland Operations Limited"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:e0:4a:34:4b:39:7f:75:2a:45:b1:28:a5:94:a3:d6:b5"
      cert_thumbprint     = "1EE4240E49F7889BFD57304E967247BDA7C2F2CB"
      cert_valid_from     = "2020-08-18"
      cert_valid_to       = "2021-08-18"

      country             = "IE"
      state               = "Dublin"
      locality            = "Dublin"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:e0:4a:34:4b:39:7f:75:2a:45:b1:28:a5:94:a3:d6:b5"
      )
}
