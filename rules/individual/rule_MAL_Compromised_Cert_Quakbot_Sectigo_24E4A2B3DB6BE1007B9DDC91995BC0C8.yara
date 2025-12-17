import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_24E4A2B3DB6BE1007B9DDC91995BC0C8 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-02-18"
      version             = "1.0"

      hash                = "2d68755335776e3de28fcd1757b7dcc07688b31c37205ce2324d92c2f419c6f0"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "FLY BETTER s.r.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "24:e4:a2:b3:db:6b:e1:00:7b:9d:dc:91:99:5b:c0:c8"
      cert_thumbprint     = "E55B27C39CBD67F647BE381AC4D5FFA8A042BA19"
      cert_valid_from     = "2022-02-18"
      cert_valid_to       = "2023-02-18"

      country             = "SK"
      state               = "Bratislavský kraj"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "24:e4:a2:b3:db:6b:e1:00:7b:9d:dc:91:99:5b:c0:c8"
      )
}
