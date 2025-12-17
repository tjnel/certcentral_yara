import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_SSL_com_316BB5E6D2D5FF1F4C2C60028E1CEC08 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-06"
      version             = "1.0"

      hash                = "cb517c016416fc55bd64a82fe1d9c5d5e05e227fa6a6878d2ec98903e1bc9ecb"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "SIA SoftWorks"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "31:6b:b5:e6:d2:d5:ff:1f:4c:2c:60:02:8e:1c:ec:08"
      cert_thumbprint     = "129C2424E2CF3CAB9F1195D0EB90337C5187C5EA"
      cert_valid_from     = "2024-08-06"
      cert_valid_to       = "2025-08-06"

      country             = "LV"
      state               = "Rīga"
      locality            = "Latgales priekšpilsēta"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "31:6b:b5:e6:d2:d5:ff:1f:4c:2c:60:02:8e:1c:ec:08"
      )
}
