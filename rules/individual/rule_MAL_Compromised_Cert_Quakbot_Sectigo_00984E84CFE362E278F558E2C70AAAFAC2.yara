import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00984E84CFE362E278F558E2C70AAAFAC2 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-12-24"
      version             = "1.0"

      hash                = "94f38d5422e546a4569120ceca7895b0b0828cffac8beb82c57135ccd82cbbd6"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Arctic Nights Äkäslompolo Oy"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:98:4e:84:cf:e3:62:e2:78:f5:58:e2:c7:0a:aa:fa:c2"
      cert_thumbprint     = "BA543D98A47AC10C6298281B7800F7F439A7EFA3"
      cert_valid_from     = "2021-12-24"
      cert_valid_to       = "2022-12-24"

      country             = "FI"
      state               = "Lappi"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:98:4e:84:cf:e3:62:e2:78:f5:58:e2:c7:0a:aa:fa:c2"
      )
}
