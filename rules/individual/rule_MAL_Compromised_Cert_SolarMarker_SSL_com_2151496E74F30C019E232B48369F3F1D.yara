import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_2151496E74F30C019E232B48369F3F1D {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-11-14"
      version             = "1.0"

      hash                = "4cb0a000097880a2e0a945005f4acba541df8d2ffd7a34afcbd88e404dcbba71"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "ТОВ \"ЛефІ\""
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "21:51:49:6e:74:f3:0c:01:9e:23:2b:48:36:9f:3f:1d"
      cert_thumbprint     = "73FEE151165DFFD1207FCE1B0BD94157EB787A11"
      cert_valid_from     = "2023-11-14"
      cert_valid_to       = "2024-11-13"

      country             = "UA"
      state               = "Dnipropetrovsk Oblast"
      locality            = "Dnipro"
      email               = "???"
      rdn_serial_number   = "45284985"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "21:51:49:6e:74:f3:0c:01:9e:23:2b:48:36:9f:3f:1d"
      )
}
