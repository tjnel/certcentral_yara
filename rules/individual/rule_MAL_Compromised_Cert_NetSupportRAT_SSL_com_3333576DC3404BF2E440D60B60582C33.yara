import "pe"

rule MAL_Compromised_Cert_NetSupportRAT_SSL_com_3333576DC3404BF2E440D60B60582C33 {
   meta:
      description         = "Detects NetSupportRAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-23"
      version             = "1.0"

      hash                = "f5ba7bdc07e9c6cc9f22ca5680e51363acd4a8e74587ee3d10bc189ea8ff123a"
      malware             = "NetSupportRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Thea Software"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "33:33:57:6d:c3:40:4b:f2:e4:40:d6:0b:60:58:2c:33"
      cert_thumbprint     = ""
      cert_valid_from     = "2024-12-23"
      cert_valid_to       = "2025-12-23"

      country             = "FR"
      state               = "Nouvelle-Aquitaine"
      locality            = "Le Bouscat"
      email               = ""
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "33:33:57:6d:c3:40:4b:f2:e4:40:d6:0b:60:58:2c:33"
      )
}
