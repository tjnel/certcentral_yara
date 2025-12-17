import "pe"

rule MAL_Compromised_Cert_SolarMarker_Certum_69FDC58EC3C51276598AE539541FE236 {
   meta:
      description         = "Detects SolarMarker with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-09-12"
      version             = "1.0"

      hash                = "336e2f4cd131ca8c6ebf87fe23ac876a119992e24b5f84d5bbf7b6fcf5c43a5d"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "DataIntegra s.r.o."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "69:fd:c5:8e:c3:c5:12:76:59:8a:e5:39:54:1f:e2:36"
      cert_thumbprint     = "FFCE9C760C6C7B16F248976F7D5E69AE79AF2DF2"
      cert_valid_from     = "2022-09-12"
      cert_valid_to       = "2023-09-12"

      country             = "SK"
      state               = "Žilinský kraj"
      locality            = "Liptovské Sliače"
      email               = "???"
      rdn_serial_number   = "50270796"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "69:fd:c5:8e:c3:c5:12:76:59:8a:e5:39:54:1f:e2:36"
      )
}
