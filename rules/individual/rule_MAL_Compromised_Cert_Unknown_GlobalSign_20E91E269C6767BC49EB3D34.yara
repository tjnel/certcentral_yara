import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_20E91E269C6767BC49EB3D34 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-08"
      version             = "1.0"

      hash                = "512a7207048876f3d3edb588847bce9beee620675dd2a280a0efd4f08b0550d6"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Bi-Test Limited Liability Company"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "20:e9:1e:26:9c:67:67:bc:49:eb:3d:34"
      cert_thumbprint     = "392603E3F1D066C037F300FFF8D777856218F8E3"
      cert_valid_from     = "2025-08-08"
      cert_valid_to       = "2026-03-14"

      country             = "KG"
      state               = "Bishkek"
      locality            = "Bishkek"
      email               = "zaharmurashev@gmail.com"
      rdn_serial_number   = "207602-3301-OOO"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "20:e9:1e:26:9c:67:67:bc:49:eb:3d:34"
      )
}
