import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_7C8A13BFC595B0DCE94BD5A1B390BA99 {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-09-22"
      version             = "1.0"

      hash                = "39102fb7bb6a74a9c8cb6d46419f9015b381199ea8524c1376672b30fffd69d2"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "ТОВ \"Трафік Девелоп ЮА\""
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "7c:8a:13:bf:c5:95:b0:dc:e9:4b:d5:a1:b3:90:ba:99"
      cert_thumbprint     = "F400439D02442BDAED6138647641627694712A83"
      cert_valid_from     = "2023-09-22"
      cert_valid_to       = "2024-09-21"

      country             = "UA"
      state               = "Rivne Oblast"
      locality            = "Rivne"
      email               = "???"
      rdn_serial_number   = "45405980"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "7c:8a:13:bf:c5:95:b0:dc:e9:4b:d5:a1:b3:90:ba:99"
      )
}
