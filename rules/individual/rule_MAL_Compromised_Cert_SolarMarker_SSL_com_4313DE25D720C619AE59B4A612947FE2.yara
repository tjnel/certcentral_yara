import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_4313DE25D720C619AE59B4A612947FE2 {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-09-29"
      version             = "1.0"

      hash                = "0dc32f351d59be068455286148d1c654287e5538e5429d12a014b0a6f9970efd"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "SPECIALIST TECHNICIANS LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "43:13:de:25:d7:20:c6:19:ae:59:b4:a6:12:94:7f:e2"
      cert_thumbprint     = "A232F94AD3C7FF530E09EB70A4EC9C8C9C0FF1D7"
      cert_valid_from     = "2023-09-29"
      cert_valid_to       = "2024-09-28"

      country             = "GB"
      state               = "England"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "14518456"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "43:13:de:25:d7:20:c6:19:ae:59:b4:a6:12:94:7f:e2"
      )
}
