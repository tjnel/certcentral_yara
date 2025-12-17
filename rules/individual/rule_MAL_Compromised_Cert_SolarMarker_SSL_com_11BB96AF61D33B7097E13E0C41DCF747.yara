import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_11BB96AF61D33B7097E13E0C41DCF747 {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-08-24"
      version             = "1.0"

      hash                = "48d7f595d98bbe45cf34f1ba7280a89c27e59de9b17fdfd8bc5d6d1cf817c321"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "D&J BROWN IDIOMAS LTDA"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "11:bb:96:af:61:d3:3b:70:97:e1:3e:0c:41:dc:f7:47"
      cert_thumbprint     = "F524AE15C6FF2D630158E2619930D230CDCFB337"
      cert_valid_from     = "2023-08-24"
      cert_valid_to       = "2024-08-09"

      country             = "BR"
      state               = "São Paulo"
      locality            = "Indaiatuba"
      email               = "???"
      rdn_serial_number   = "40.461.953/0001-71"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "11:bb:96:af:61:d3:3b:70:97:e1:3e:0c:41:dc:f7:47"
      )
}
