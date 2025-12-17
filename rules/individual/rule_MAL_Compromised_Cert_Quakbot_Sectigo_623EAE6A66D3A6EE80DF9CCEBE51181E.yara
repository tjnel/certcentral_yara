import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_623EAE6A66D3A6EE80DF9CCEBE51181E {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-04-14"
      version             = "1.0"

      hash                = "8cc8f32b2f44e84325e5153ec4fd60c31a35884220e7c36b753550356d6a25c8"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "GAIN AI LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "62:3e:ae:6a:66:d3:a6:ee:80:df:9c:ce:be:51:18:1e"
      cert_thumbprint     = "F1D238E66A6537393D738E4CEE813A2DB72A09C5"
      cert_valid_from     = "2022-04-14"
      cert_valid_to       = "2023-04-14"

      country             = "GB"
      state               = "West Midlands"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "62:3e:ae:6a:66:d3:a6:ee:80:df:9c:ce:be:51:18:1e"
      )
}
