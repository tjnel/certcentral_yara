import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_13794371C052EC0559E9B492ABB25C26 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-09-04"
      version             = "1.0"

      hash                = "0652d513a2c43aaabbb806eeda3e035aa3b12449a718610d42453896d9f97751"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Carmel group LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "13:79:43:71:c0:52:ec:05:59:e9:b4:92:ab:b2:5c:26"
      cert_thumbprint     = "4D127CE781A74AF7AAB1373A5AF2625FFB27E2FA"
      cert_valid_from     = "2020-09-04"
      cert_valid_to       = "2021-09-04"

      country             = "RU"
      state               = "???"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "13:79:43:71:c0:52:ec:05:59:e9:b4:92:ab:b2:5c:26"
      )
}
