import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00D3AEE8ABB9948844A3AC1C04CC7E6BDF {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-12-30"
      version             = "1.0"

      hash                = "cd8a94e42e7119a3f1b5117151b7bb2fe4a777f221581b2dae0c2cf0e8ddedf2"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "HOUSE 9A s.r.o"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:d3:ae:e8:ab:b9:94:88:44:a3:ac:1c:04:cc:7e:6b:df"
      cert_thumbprint     = "E5732E135DD2336153938B25B82E0D1F392A4449"
      cert_valid_from     = "2021-12-30"
      cert_valid_to       = "2022-12-30"

      country             = "SK"
      state               = "Žilinský kraj"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:d3:ae:e8:ab:b9:94:88:44:a3:ac:1c:04:cc:7e:6b:df"
      )
}
