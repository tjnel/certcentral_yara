import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_19C82A677E106CC31FC9BA4B660CECFB {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-12-14"
      version             = "1.0"

      hash                = "c249477d921abc7aefb41f46c489c215f807a5d9a9aa68c426295304895eaf10"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Gajanan Consulting Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "19:c8:2a:67:7e:10:6c:c3:1f:c9:ba:4b:66:0c:ec:fb"
      cert_thumbprint     = "7D2B6E2904206DA8734E02F34DFFCEB833D934DC"
      cert_valid_from     = "2022-12-14"
      cert_valid_to       = "2023-12-14"

      country             = "CA"
      state               = "Ontario"
      locality            = "Toronto"
      email               = "???"
      rdn_serial_number   = "1008676-2"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "19:c8:2a:67:7e:10:6c:c3:1f:c9:ba:4b:66:0c:ec:fb"
      )
}
