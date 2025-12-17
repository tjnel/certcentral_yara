import "pe"

rule MAL_Compromised_Cert_PSBackdoor_GlobalSign_12F7A735DF3603B17CDE6352 {
   meta:
      description         = "Detects PSBackdoor with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-15"
      version             = "1.0"

      hash                = "e6786d6e0ea80175944e470dcccf61b322f3fadd438c975e0aee31705d9de7b6"
      malware             = "PSBackdoor"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LIBERTY TRADE LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "12:f7:a7:35:df:36:03:b1:7c:de:63:52"
      cert_thumbprint     = "0FD7FB5E430395867D93AACB46C98DEB102BBC17"
      cert_valid_from     = "2025-11-15"
      cert_valid_to       = "2026-02-08"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "12:f7:a7:35:df:36:03:b1:7c:de:63:52"
      )
}
