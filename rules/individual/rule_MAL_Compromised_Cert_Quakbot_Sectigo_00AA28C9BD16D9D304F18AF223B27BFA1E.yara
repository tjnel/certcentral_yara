import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00AA28C9BD16D9D304F18AF223B27BFA1E {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-01-27"
      version             = "1.0"

      hash                = "68199ddf000a34ebcf9cedb1d45eefb0319f0a802197e64c4658e7ea9f04a943"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Tecno trade d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:aa:28:c9:bd:16:d9:d3:04:f1:8a:f2:23:b2:7b:fa:1e"
      cert_thumbprint     = "252E076F4AC2A0EBA7BC1F62C6FB9B1137D4754E"
      cert_valid_from     = "2021-01-27"
      cert_valid_to       = "2022-01-27"

      country             = "SI"
      state               = "???"
      locality            = "Koper"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:aa:28:c9:bd:16:d9:d3:04:f1:8a:f2:23:b2:7b:fa:1e"
      )
}
