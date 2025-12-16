import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_0A392F03DED5D73CDEEDA75052A57176 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-04-27"
      version             = "1.0"

      hash                = "f9bbfe101624f224998b0ad845512014efa6a42265ebe45e8e13a28a775d39b2"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "FLOWER COMPUTERS LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "0a:39:2f:03:de:d5:d7:3c:de:ed:a7:50:52:a5:71:76"
      cert_thumbprint     = "0979567833867AB7630F462DC4214D6CFE202660"
      cert_valid_from     = "2022-04-27"
      cert_valid_to       = "2023-04-27"

      country             = "GB"
      state               = "Dorset"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "0a:39:2f:03:de:d5:d7:3c:de:ed:a7:50:52:a5:71:76"
      )
}
