import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_5C7E78F53C31D6AA5B45DE14B47EB5C4 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-01-24"
      version             = "1.0"

      hash                = "d041ef7ec1117e7947220390fb169788d96ae373471029f83fe9a0858a92f39e"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Cubic Information Systems, UAB"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "5c:7e:78:f5:3c:31:d6:aa:5b:45:de:14:b4:7e:b5:c4"
      cert_thumbprint     = "D8CC9100FB36F8CDD372F9FEE9F550C2F2E2C99D"
      cert_valid_from     = "2020-01-24"
      cert_valid_to       = "2021-01-23"

      country             = "LT"
      state               = "Vilnius"
      locality            = "Vilnius"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "5c:7e:78:f5:3c:31:d6:aa:5b:45:de:14:b4:7e:b5:c4"
      )
}
