import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_3990362C34015CE4C23ECC3377FD3C06 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-12-01"
      version             = "1.0"

      hash                = "7308f0965c7fa1b09efb2c252c2868b77e52527dac3f33eea697148bda017c48"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "RZOH ApS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "39:90:36:2c:34:01:5c:e4:c2:3e:cc:33:77:fd:3c:06"
      cert_thumbprint     = "48444DEC9D6839734D8383B110FAABE05E697D45"
      cert_valid_from     = "2020-12-01"
      cert_valid_to       = "2021-12-01"

      country             = "DK"
      state               = "???"
      locality            = "Charlottenlund"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "39:90:36:2c:34:01:5c:e4:c2:3e:cc:33:77:fd:3c:06"
      )
}
