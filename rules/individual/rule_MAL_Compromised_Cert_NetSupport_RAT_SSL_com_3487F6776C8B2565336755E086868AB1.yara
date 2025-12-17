import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_SSL_com_3487F6776C8B2565336755E086868AB1 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-16"
      version             = "1.0"

      hash                = "e70ae269c2ce3d77bb5b5494bd64be7154d542ab84948fed6c68addae735bbf4"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Huus Consulting ApS"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "34:87:f6:77:6c:8b:25:65:33:67:55:e0:86:86:8a:b1"
      cert_thumbprint     = "81F223057B0FBB6DAF6FC1C2BE8315E603E9ECA8"
      cert_valid_from     = "2024-07-16"
      cert_valid_to       = "2025-07-15"

      country             = "DK"
      state               = "Capital Region of Denmark"
      locality            = "Copenhagen"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "34:87:f6:77:6c:8b:25:65:33:67:55:e0:86:86:8a:b1"
      )
}
