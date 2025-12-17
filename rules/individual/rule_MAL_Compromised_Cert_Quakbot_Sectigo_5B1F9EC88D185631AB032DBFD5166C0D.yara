import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_5B1F9EC88D185631AB032DBFD5166C0D {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-06-24"
      version             = "1.0"

      hash                = "42bc9b623f70e46d6aab4910d8c75221aecf89a00756a61b21f952eea13a446c"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "TOPFLIGHT GROUP LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "5b:1f:9e:c8:8d:18:56:31:ab:03:2d:bf:d5:16:6c:0d"
      cert_thumbprint     = "79E48E1BAB6039D7088FECBF10257E3E177599F5"
      cert_valid_from     = "2022-06-24"
      cert_valid_to       = "2023-06-24"

      country             = "GB"
      state               = "Lanarkshire"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "5b:1f:9e:c8:8d:18:56:31:ab:03:2d:bf:d5:16:6c:0d"
      )
}
