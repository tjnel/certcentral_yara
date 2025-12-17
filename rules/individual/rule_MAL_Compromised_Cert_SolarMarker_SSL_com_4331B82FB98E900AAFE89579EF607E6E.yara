import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_4331B82FB98E900AAFE89579EF607E6E {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-09-26"
      version             = "1.0"

      hash                = "bd6d8c48c1faad08dc110393275243acb0f5c7c8884d8c6663d2538cced4ad8e"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Bau Yannis GmbH"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "43:31:b8:2f:b9:8e:90:0a:af:e8:95:79:ef:60:7e:6e"
      cert_thumbprint     = "3B44F0365EC584E68579DC3B1C2B0B88FD952CE3"
      cert_valid_from     = "2023-09-26"
      cert_valid_to       = "2024-09-25"

      country             = "CH"
      state               = "Solothurn"
      locality            = "Grenchen"
      email               = "???"
      rdn_serial_number   = "CHE-166.264.872"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "43:31:b8:2f:b9:8e:90:0a:af:e8:95:79:ef:60:7e:6e"
      )
}
