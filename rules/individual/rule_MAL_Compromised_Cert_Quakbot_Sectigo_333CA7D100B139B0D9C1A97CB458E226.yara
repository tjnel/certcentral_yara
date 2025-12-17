import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_333CA7D100B139B0D9C1A97CB458E226 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-12-16"
      version             = "1.0"

      hash                = "45406dae6b2c7383a3464de9112940cc9a388767fa867f17bc2a9c904861b358"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "FSE, d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "33:3c:a7:d1:00:b1:39:b0:d9:c1:a9:7c:b4:58:e2:26"
      cert_thumbprint     = "D618CF7EF3A674FF1EA50800B4D965DE0FF463CB"
      cert_valid_from     = "2020-12-16"
      cert_valid_to       = "2021-12-16"

      country             = "SI"
      state               = "???"
      locality            = "Ljubljana"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "33:3c:a7:d1:00:b1:39:b0:d9:c1:a9:7c:b4:58:e2:26"
      )
}
