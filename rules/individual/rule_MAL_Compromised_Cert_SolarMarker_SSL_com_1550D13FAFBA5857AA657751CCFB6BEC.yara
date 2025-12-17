import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_1550D13FAFBA5857AA657751CCFB6BEC {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-08-09"
      version             = "1.0"

      hash                = "4f349e005eb9cebef10044b3f4aa181ea75cf9c107fb0683931397b2ea06a86d"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "BAAAD KITTY LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "15:50:d1:3f:af:ba:58:57:aa:65:77:51:cc:fb:6b:ec"
      cert_thumbprint     = "460D117585E29A630CC701BD1DDF091BB7E73722"
      cert_valid_from     = "2023-08-09"
      cert_valid_to       = "2024-08-08"

      country             = "GB"
      state               = "???"
      locality            = "St. Albans"
      email               = "???"
      rdn_serial_number   = "11809951"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "15:50:d1:3f:af:ba:58:57:aa:65:77:51:cc:fb:6b:ec"
      )
}
