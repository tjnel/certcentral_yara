import "pe"

rule MAL_Compromised_Cert_AsyncRAT_GlobalSign_6D697B15A91B985E9398396C {
   meta:
      description         = "Detects AsyncRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-14"
      version             = "1.0"

      hash                = "330d82b2eda6678862e317d8c8e51dad2e0463ba7dda10a9df6498440eaf2968"
      malware             = "AsyncRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "KIRAANEVALA TRADING PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "6d:69:7b:15:a9:1b:98:5e:93:98:39:6c"
      cert_thumbprint     = "7176E99BB4A5EBDB6E65B0AA8DCB571D2739AF30"
      cert_valid_from     = "2025-01-14"
      cert_valid_to       = "2026-01-15"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "daphinefregiawaq38@gmail.com"
      rdn_serial_number   = "U74900RJ2015PTC048808"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "6d:69:7b:15:a9:1b:98:5e:93:98:39:6c"
      )
}
