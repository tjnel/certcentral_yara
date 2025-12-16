import "pe"

rule MAL_Compromised_Cert_SolarMarker_GlobalSign_182010E6F30A0FDCC3F1BD44 {
   meta:
      description         = "Detects SolarMarker with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-06-20"
      version             = "1.0"

      hash                = "59b1140b830a98ad213d6e92abd8329d3485cb530143c2ad7cff70362c4c181d"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "LAABAI LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "18:20:10:e6:f3:0a:0f:dc:c3:f1:bd:44"
      cert_thumbprint     = "74B954DACFB6A43782F82C7ED3A2DFA3244E3543"
      cert_valid_from     = "2023-06-20"
      cert_valid_to       = "2024-06-20"

      country             = "GB"
      state               = "Wales"
      locality            = "Bargoed"
      email               = "???"
      rdn_serial_number   = "11455947"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "18:20:10:e6:f3:0a:0f:dc:c3:f1:bd:44"
      )
}
