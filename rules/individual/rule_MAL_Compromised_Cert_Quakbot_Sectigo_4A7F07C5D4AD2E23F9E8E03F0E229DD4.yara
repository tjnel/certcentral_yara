import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_4A7F07C5D4AD2E23F9E8E03F0E229DD4 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-12-23"
      version             = "1.0"

      hash                = "8b843d780403b64d562c38c56dcd9cc8abe2c70cc5324660cbd2757e41fd5057"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Danalis LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "4a:7f:07:c5:d4:ad:2e:23:f9:e8:e0:3f:0e:22:9d:d4"
      cert_thumbprint     = "B37E7F9040C4ADC6D29DA6829C7A35A2F6A56FDB"
      cert_valid_from     = "2020-12-23"
      cert_valid_to       = "2021-12-23"

      country             = "RU"
      state               = "???"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "4a:7f:07:c5:d4:ad:2e:23:f9:e8:e0:3f:0e:22:9d:d4"
      )
}
