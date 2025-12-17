import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00EA720222D92DC8D48E3B3C3B0FC360A6 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-12-16"
      version             = "1.0"

      hash                = "c972346b25a36cb3ddaeb4ede844d18711cbbf8226d74075879e5d8b49b8d46c"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "CAVANAGH NETS LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:ea:72:02:22:d9:2d:c8:d4:8e:3b:3c:3b:0f:c3:60:a6"
      cert_thumbprint     = "522D0F1CA87EF784994DFD63CB0919722DFDB79F"
      cert_valid_from     = "2020-12-16"
      cert_valid_to       = "2021-12-16"

      country             = "IE"
      state               = "???"
      locality            = "GREENCASTLE"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:ea:72:02:22:d9:2d:c8:d4:8e:3b:3c:3b:0f:c3:60:a6"
      )
}
