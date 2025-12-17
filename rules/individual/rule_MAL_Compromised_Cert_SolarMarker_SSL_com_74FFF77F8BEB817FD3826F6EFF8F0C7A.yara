import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_74FFF77F8BEB817FD3826F6EFF8F0C7A {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-09-19"
      version             = "1.0"

      hash                = "777cb8aae1e77e841b4981965198f62e60e55a4f910120980dc5ad997ab71fb5"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "ТОВ \"РЕОВГУЦ\""
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "74:ff:f7:7f:8b:eb:81:7f:d3:82:6f:6e:ff:8f:0c:7a"
      cert_thumbprint     = "7E0D8019997F318C1A6EFAF056068182CCFB0F7B"
      cert_valid_from     = "2023-09-19"
      cert_valid_to       = "2024-09-18"

      country             = "UA"
      state               = "Kharkiv Oblast"
      locality            = "Balakliya"
      email               = "???"
      rdn_serial_number   = "45285334"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "74:ff:f7:7f:8b:eb:81:7f:d3:82:6f:6e:ff:8f:0c:7a"
      )
}
