import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_SSL_com_2E833BA760E021C8C7EE72FA6EE6046F {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-28"
      version             = "1.0"

      hash                = "315cf861344efad52397b22e35fc103a1111508497b49554fcc138646a2a7129"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Cx Software Sp. z o.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "2e:83:3b:a7:60:e0:21:c8:c7:ee:72:fa:6e:e6:04:6f"
      cert_thumbprint     = "23E5884A1489075C121DBC03BF6C718878109576"
      cert_valid_from     = "2025-05-28"
      cert_valid_to       = "2026-02-04"

      country             = "PL"
      state               = "Województwo wielkopolskie"
      locality            = "Poznań"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "2e:83:3b:a7:60:e0:21:c8:c7:ee:72:fa:6e:e6:04:6f"
      )
}
