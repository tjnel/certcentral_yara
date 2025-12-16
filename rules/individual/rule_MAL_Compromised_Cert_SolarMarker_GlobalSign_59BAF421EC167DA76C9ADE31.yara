import "pe"

rule MAL_Compromised_Cert_SolarMarker_GlobalSign_59BAF421EC167DA76C9ADE31 {
   meta:
      description         = "Detects SolarMarker with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-07-10"
      version             = "1.0"

      hash                = "1160da03685be4abedafa4f03b02cdf3f3242bc1d6985187acf281f5c7e46168"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Repeat Business Ltd"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "59:ba:f4:21:ec:16:7d:a7:6c:9a:de:31"
      cert_thumbprint     = "E04AD07474D36464419F5C94FC0857F267362CAA"
      cert_valid_from     = "2023-07-10"
      cert_valid_to       = "2024-07-10"

      country             = "GB"
      state               = "London"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "14044303"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "59:ba:f4:21:ec:16:7d:a7:6c:9a:de:31"
      )
}
