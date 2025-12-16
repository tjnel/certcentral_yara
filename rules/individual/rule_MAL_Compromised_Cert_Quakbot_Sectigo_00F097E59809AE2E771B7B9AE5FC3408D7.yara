import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00F097E59809AE2E771B7B9AE5FC3408D7 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-10-07"
      version             = "1.0"

      hash                = "96e21a6d02770fdff74ac912154f8c7c7a934d7236360485920c8550fa0050a1"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "ABEL RENOVATIONS, INC."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:f0:97:e5:98:09:ae:2e:77:1b:7b:9a:e5:fc:34:08:d7"
      cert_thumbprint     = "AC0E2E057CADD25B569B10BB5760C1A7E17569AB"
      cert_valid_from     = "2020-10-07"
      cert_valid_to       = "2021-10-07"

      country             = "US"
      state               = "Florida"
      locality            = "JACKSONVILLE"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:f0:97:e5:98:09:ae:2e:77:1b:7b:9a:e5:fc:34:08:d7"
      )
}
