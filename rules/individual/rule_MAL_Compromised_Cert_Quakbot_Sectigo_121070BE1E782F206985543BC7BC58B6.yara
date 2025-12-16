import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_121070BE1E782F206985543BC7BC58B6 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-03-21"
      version             = "1.0"

      hash                = "423e9834d7e38533008abe7196be51ca3d424a16c9a96fd4b2638933eab8bb83"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Prod Can Holdings Inc."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "12:10:70:be:1e:78:2f:20:69:85:54:3b:c7:bc:58:b6"
      cert_thumbprint     = "2AA8D5E1316B791C90F5F3AAB909467D9B16492D"
      cert_valid_from     = "2022-03-21"
      cert_valid_to       = "2023-03-21"

      country             = "CA"
      state               = "Ontario"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "12:10:70:be:1e:78:2f:20:69:85:54:3b:c7:bc:58:b6"
      )
}
