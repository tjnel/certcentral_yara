import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_0EF9DCEF244E302160FEB44B41E24F1F {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-05"
      version             = "1.0"

      hash                = "55da66e72382877954b3d050a9ca5e4daad614d5b0c788e61187184b7352e768"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "TRACK PROJECT SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "0e:f9:dc:ef:24:4e:30:21:60:fe:b4:4b:41:e2:4f:1f"
      cert_thumbprint     = "782FDCD807051B0B48E690F2AAC1B6F58A48828A"
      cert_valid_from     = "2024-04-05"
      cert_valid_to       = "2025-04-05"

      country             = "PL"
      state               = "Malopolskie"
      locality            = "Krakow"
      email               = "???"
      rdn_serial_number   = "0000570348"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "0e:f9:dc:ef:24:4e:30:21:60:fe:b4:4b:41:e2:4f:1f"
      )
}
