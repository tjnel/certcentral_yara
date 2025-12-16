import "pe"

rule MAL_Compromised_Cert_Latrodectus_GlobalSign_28F072020D6F9826725E8D8B {
   meta:
      description         = "Detects Latrodectus with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-14"
      version             = "1.0"

      hash                = "631f88a97cd1f096d9d923538e299b12e1f441895e31ada5b522e80c8da84777"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Gruzoperevozchik"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "28:f0:72:02:0d:6f:98:26:72:5e:8d:8b"
      cert_thumbprint     = "AA3914223892DCD1F1C4318E92672597484CABCF"
      cert_valid_from     = "2025-07-14"
      cert_valid_to       = "2026-07-15"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "28:f0:72:02:0d:6f:98:26:72:5e:8d:8b"
      )
}
