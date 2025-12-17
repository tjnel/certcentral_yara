import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_016836311FC39FBB8E6F308BB03CC2B3 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-10-13"
      version             = "1.0"

      hash                = "91020b6ada47f05e9941da3d5fc747a4bdf088e30fdbf010b50ce9ccf0de0cc6"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "SERVICE STREAM LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "01:68:36:31:1f:c3:9f:bb:8e:6f:30:8b:b0:3c:c2:b3"
      cert_thumbprint     = "C23CC34AF4B7A019030706F33B72542CD9A192B0"
      cert_valid_from     = "2020-10-13"
      cert_valid_to       = "2021-10-13"

      country             = "AU"
      state               = "Victoria"
      locality            = "Melbourne"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "01:68:36:31:1f:c3:9f:bb:8e:6f:30:8b:b0:3c:c2:b3"
      )
}
