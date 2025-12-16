import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00E267FDBDC16F22E8185D35C437F84C87 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-12-01"
      version             = "1.0"

      hash                = "4767f1d796361381636e0a0f6815346e85e23e441fa9e281baa17fc93910117d"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "APOTHEKA, s.r.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:e2:67:fd:bd:c1:6f:22:e8:18:5d:35:c4:37:f8:4c:87"
      cert_thumbprint     = "CDF4A69402936ECE82F3F9163E6CC648BCBB2680"
      cert_valid_from     = "2020-12-01"
      cert_valid_to       = "2021-12-01"

      country             = "SK"
      state               = "???"
      locality            = "Bratislava"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:e2:67:fd:bd:c1:6f:22:e8:18:5d:35:c4:37:f8:4c:87"
      )
}
