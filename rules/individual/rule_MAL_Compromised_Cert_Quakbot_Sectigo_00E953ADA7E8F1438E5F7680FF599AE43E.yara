import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00E953ADA7E8F1438E5F7680FF599AE43E {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-03"
      version             = "1.0"

      hash                = "2606bf8f473dee7f8407db99323d14f8c241c25db538b20dfe7fb368c46b4278"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "KULBYT LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:e9:53:ad:a7:e8:f1:43:8e:5f:76:80:ff:59:9a:e4:3e"
      cert_thumbprint     = "D994C0AFCFF039229E7CE86E2926B2B29430544B"
      cert_valid_from     = "2021-03-03"
      cert_valid_to       = "2022-03-03"

      country             = "RU"
      state               = "???"
      locality            = "Saint Petersburg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:e9:53:ad:a7:e8:f1:43:8e:5f:76:80:ff:59:9a:e4:3e"
      )
}
