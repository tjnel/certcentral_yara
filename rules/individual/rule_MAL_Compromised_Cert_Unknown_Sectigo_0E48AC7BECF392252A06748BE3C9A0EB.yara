import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_0E48AC7BECF392252A06748BE3C9A0EB {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-20"
      version             = "1.0"

      hash                = "6384e81660b474e430857852fdc708173e76cdb4b11b972721b54dd99f071aa4"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shanghai Chuanjin Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "0e:48:ac:7b:ec:f3:92:25:2a:06:74:8b:e3:c9:a0:eb"
      cert_thumbprint     = "85E39165D8EC322CEDFB41ADC4A04E76A14077B0"
      cert_valid_from     = "2025-10-20"
      cert_valid_to       = "2027-01-18"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "0e:48:ac:7b:ec:f3:92:25:2a:06:74:8b:e3:c9:a0:eb"
      )
}
