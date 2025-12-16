import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00A03EA3A4FA772B17037A0B80F1F968AA {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-12-16"
      version             = "1.0"

      hash                = "fc7a4edf9d9984d4a53b4296f0d0160436144bc5631b8c5b445a86f3bfa9ff61"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "DREVOKAPITAL, s.r.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:a0:3e:a3:a4:fa:77:2b:17:03:7a:0b:80:f1:f9:68:aa"
      cert_thumbprint     = "D3145F5D55A7399C46AE011711B479985459D39A"
      cert_valid_from     = "2020-12-16"
      cert_valid_to       = "2021-12-16"

      country             = "SK"
      state               = "???"
      locality            = "Svidník"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:a0:3e:a3:a4:fa:77:2b:17:03:7a:0b:80:f1:f9:68:aa"
      )
}
