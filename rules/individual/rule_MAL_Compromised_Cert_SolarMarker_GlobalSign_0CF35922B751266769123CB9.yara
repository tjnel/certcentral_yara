import "pe"

rule MAL_Compromised_Cert_SolarMarker_GlobalSign_0CF35922B751266769123CB9 {
   meta:
      description         = "Detects SolarMarker with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-24"
      version             = "1.0"

      hash                = "315d36da6305f267f36216733590babcbcb405c4fc88935d2f3a7bf610cf98fe"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "SMART AC VIET NAM TM & DV JOINT STOCK COMPANY"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0c:f3:59:22:b7:51:26:67:69:12:3c:b9"
      cert_thumbprint     = "C07079D74187CBD6C3462DED3AE9CC57A52B788A"
      cert_valid_from     = "2024-05-24"
      cert_valid_to       = "2025-05-25"

      country             = "VN"
      state               = "Ha Noi"
      locality            = "Ha Noi"
      email               = "???"
      rdn_serial_number   = "0110012801"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0c:f3:59:22:b7:51:26:67:69:12:3c:b9"
      )
}
