import "pe"

rule MAL_Compromised_Cert_FakeNordpass_GlobalSign_6562890A00BB9C7A0A80695A {
   meta:
      description         = "Detects FakeNordpass with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-31"
      version             = "1.0"

      hash                = "10de1e14a9a64af2d06fff3741cb870d21bcd7508e6b645a7e98f11d05b811be"
      malware             = "FakeNordpass"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Yurisk LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "65:62:89:0a:00:bb:9c:7a:0a:80:69:5a"
      cert_thumbprint     = "50FA33EBD90F7FEB9FF4C1F89BCD5BDA3BD0D928"
      cert_valid_from     = "2025-03-31"
      cert_valid_to       = "2026-04-01"

      country             = "RU"
      state               = "Tula Oblast"
      locality            = "Tula"
      email               = "???"
      rdn_serial_number   = "1217100007222"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "65:62:89:0a:00:bb:9c:7a:0a:80:69:5a"
      )
}
