import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_6CDA1A0D2917A790C24B0F3FBDD9F7EB {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-06-07"
      version             = "1.0"

      hash                = "d4debb62f43fb37f8ad0968499d2d48d3cfad20f4ed20d8b3fe9e4759fd95d68"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Austin Software Company LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "6c:da:1a:0d:29:17:a7:90:c2:4b:0f:3f:bd:d9:f7:eb"
      cert_thumbprint     = "EB2463B6461F009034605620FF9AE2494A8FE5C8"
      cert_valid_from     = "2023-06-07"
      cert_valid_to       = "2024-06-05"

      country             = "US"
      state               = "California"
      locality            = "Palm Desert"
      email               = "???"
      rdn_serial_number   = "7306616"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "6c:da:1a:0d:29:17:a7:90:c2:4b:0f:3f:bd:d9:f7:eb"
      )
}
