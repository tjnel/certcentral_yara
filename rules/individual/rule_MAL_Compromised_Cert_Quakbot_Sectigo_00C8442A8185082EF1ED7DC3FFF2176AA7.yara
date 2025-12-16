import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00C8442A8185082EF1ED7DC3FFF2176AA7 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-29"
      version             = "1.0"

      hash                = "53214f4721ef1221632de09fd853580056811ac6632b517d77fb326956129530"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Ambidekstr LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:c8:44:2a:81:85:08:2e:f1:ed:7d:c3:ff:f2:17:6a:a7"
      cert_thumbprint     = "C403C50A6FDFB39B9197EFBA4F253715C346090D"
      cert_valid_from     = "2021-03-29"
      cert_valid_to       = "2022-03-29"

      country             = "RU"
      state               = "???"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:c8:44:2a:81:85:08:2e:f1:ed:7d:c3:ff:f2:17:6a:a7"
      )
}
