import "pe"

rule MAL_Compromised_Cert_Silence_Sectigo_7D27332C3CB3A382A4FD232C5C66A2 {
   meta:
      description         = "Detects Silence with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-06-17"
      version             = "1.0"

      hash                = "2d50b03a92445ba53ae147d0b97c494858c86a56fe037c44bc0edabb902420f7"
      malware             = "Silence"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MALVINA RECRUITMENT LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "7d:27:33:2c:3c:b3:a3:82:a4:fd:23:2c:5c:66:a2"
      cert_thumbprint     = "1F37FD71AC5AF2F206B0E995C251A7FDAA0D6E99"
      cert_valid_from     = "2022-06-17"
      cert_valid_to       = "2023-06-17"

      country             = "GB"
      state               = "London"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "7d:27:33:2c:3c:b3:a3:82:a4:fd:23:2c:5c:66:a2"
      )
}
