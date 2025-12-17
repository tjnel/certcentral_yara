import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_Certum_5D0F5A3545E7F903EA79DB0E57235288 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-11"
      version             = "1.0"

      hash                = "bae3c4cfcb9525a6b024d0f69c34d040133474fa3f8dd9007179828e234708fa"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "BERCIS Software SIA"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "5d:0f:5a:35:45:e7:f9:03:ea:79:db:0e:57:23:52:88"
      cert_thumbprint     = "4919C99F5826B6E47218B2F59CEBBE6A1CF0E898"
      cert_valid_from     = "2024-10-11"
      cert_valid_to       = "2025-10-11"

      country             = "LV"
      state               = "???"
      locality            = "Riga"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "5d:0f:5a:35:45:e7:f9:03:ea:79:db:0e:57:23:52:88"
      )
}
