import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_37F3384B16D4EEF0A9B3344B50F1D8A3 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-01-27"
      version             = "1.0"

      hash                = "c0f3d4a44486b91a5cb4911608f036ce303b3020aa90cbe5d79c35bc84e1ad5b"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Sore Loser Games ApS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "37:f3:38:4b:16:d4:ee:f0:a9:b3:34:4b:50:f1:d8:a3"
      cert_thumbprint     = "3FCDCF15C35EF74DC48E1573AD1170B11A623B40"
      cert_valid_from     = "2021-01-27"
      cert_valid_to       = "2022-01-27"

      country             = "DK"
      state               = "Sjælland"
      locality            = "Roskilde"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "37:f3:38:4b:16:d4:ee:f0:a9:b3:34:4b:50:f1:d8:a3"
      )
}
