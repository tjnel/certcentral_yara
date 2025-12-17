import "pe"

rule MAL_Compromised_Cert_SolarMarker_GlobalSign_3FAC2FCD5CDFBDE7E9EF0C51 {
   meta:
      description         = "Detects SolarMarker with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-06-20"
      version             = "1.0"

      hash                = "90a377b69113082ec2789371e02043277fbf8595a6f1f7cd1c6a70493381ab80"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "FASTIDIOUS ACCOUNTANTS LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3f:ac:2f:cd:5c:df:bd:e7:e9:ef:0c:51"
      cert_thumbprint     = "471D77405809AFB4DFBFE9A74FAD917721219957"
      cert_valid_from     = "2023-06-20"
      cert_valid_to       = "2024-06-20"

      country             = "GB"
      state               = "Scotland"
      locality            = "Edinburgh"
      email               = "???"
      rdn_serial_number   = "SC711342"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3f:ac:2f:cd:5c:df:bd:e7:e9:ef:0c:51"
      )
}
