import "pe"

rule MAL_Compromised_Cert_SolarMarker_Entrust_192776242ED08D537676143D67B5D23A {
   meta:
      description         = "Detects SolarMarker with compromised cert (Entrust)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-01-18"
      version             = "1.0"

      hash                = "5bccb6950b0aad0956ab9a0eb02e503fc613d4744b9f396fdbcb2fd965e69542"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Gurung Solutions Ltd"
      cert_issuer_short   = "Entrust"
      cert_issuer         = "Entrust Extended Validation Code Signing CA - EVCS2"
      cert_serial         = "19:27:76:24:2e:d0:8d:53:76:76:14:3d:67:b5:d2:3a"
      cert_thumbprint     = "F32C6501BAC6AF92DC18B60801B506CB986B2B80"
      cert_valid_from     = "2023-01-18"
      cert_valid_to       = "2024-01-18"

      country             = "GB"
      state               = "???"
      locality            = "Edgware"
      email               = "???"
      rdn_serial_number   = "12359207"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Entrust Extended Validation Code Signing CA - EVCS2" and
         sig.serial == "19:27:76:24:2e:d0:8d:53:76:76:14:3d:67:b5:d2:3a"
      )
}
