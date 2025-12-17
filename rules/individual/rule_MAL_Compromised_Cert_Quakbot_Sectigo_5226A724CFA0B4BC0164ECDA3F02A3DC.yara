import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_5226A724CFA0B4BC0164ECDA3F02A3DC {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-03-15"
      version             = "1.0"

      hash                = "de3ace90ae7600dd07a646040f20b96a426bea44d6747e83ea903ea50f70372f"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "VALENTE SP Z O O"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "52:26:a7:24:cf:a0:b4:bc:01:64:ec:da:3f:02:a3:dc"
      cert_thumbprint     = "111E36502A8F8BCBF8418FDA751EA57EA6710919"
      cert_valid_from     = "2022-03-15"
      cert_valid_to       = "2023-03-15"

      country             = "PL"
      state               = "Śląskie"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "52:26:a7:24:cf:a0:b4:bc:01:64:ec:da:3f:02:a3:dc"
      )
}
