import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_4E7545C9FC5938F5198AB9F1749CA31C {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-02-26"
      version             = "1.0"

      hash                = "4b485f8f1809545de7951d651893358ea247b2788811ab09654ded91fd2449b3"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "For M d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "4e:75:45:c9:fc:59:38:f5:19:8a:b9:f1:74:9c:a3:1c"
      cert_thumbprint     = "7A49677C535A13D0A9B6DEB539D084FF431A5B54"
      cert_valid_from     = "2021-02-26"
      cert_valid_to       = "2022-02-26"

      country             = "SI"
      state               = "???"
      locality            = "Škofja Loka"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "4e:75:45:c9:fc:59:38:f5:19:8a:b9:f1:74:9c:a3:1c"
      )
}
