import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00D59A05955A4A421500F9561CE983AAC4 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-09-30"
      version             = "1.0"

      hash                = "f0329494b1a9a26aac06e2606c95e31167035d8f576ed8773664d7578913cf36"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Olymp LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:d5:9a:05:95:5a:4a:42:15:00:f9:56:1c:e9:83:aa:c4"
      cert_thumbprint     = "0F131A77C53A2123AD8C57A2110BE44FE73473DE"
      cert_valid_from     = "2020-09-30"
      cert_valid_to       = "2021-09-04"

      country             = "RU"
      state               = "???"
      locality            = "Saint Petersburg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:d5:9a:05:95:5a:4a:42:15:00:f9:56:1c:e9:83:aa:c4"
      )
}
