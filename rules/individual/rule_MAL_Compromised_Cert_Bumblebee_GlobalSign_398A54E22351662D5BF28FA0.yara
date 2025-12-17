import "pe"

rule MAL_Compromised_Cert_Bumblebee_GlobalSign_398A54E22351662D5BF28FA0 {
   meta:
      description         = "Detects Bumblebee with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-30"
      version             = "1.0"

      hash                = "1ba85af9be3e263befdaac86084f96b014684c8d3a85d0572ca1113e52a4fa4d"
      malware             = "Bumblebee"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Leighton"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "39:8a:54:e2:23:51:66:2d:5b:f2:8f:a0"
      cert_thumbprint     = "65B4E7E70DC770D59FC305E58410049228616916"
      cert_valid_from     = "2025-05-30"
      cert_valid_to       = "2026-05-31"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "5157746205690"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "39:8a:54:e2:23:51:66:2d:5b:f2:8f:a0"
      )
}
