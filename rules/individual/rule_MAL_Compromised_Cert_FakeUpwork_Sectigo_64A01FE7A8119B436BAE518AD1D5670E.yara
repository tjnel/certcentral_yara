import "pe"

rule MAL_Compromised_Cert_FakeUpwork_Sectigo_64A01FE7A8119B436BAE518AD1D5670E {
   meta:
      description         = "Detects FakeUpwork with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-12"
      version             = "1.0"

      hash                = "1b4f9d724e345ca57ec443deca90e167d2ce1117d56ecf01831faa9104517b9d"
      malware             = "FakeUpwork"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "StarServicing LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "64:a0:1f:e7:a8:11:9b:43:6b:ae:51:8a:d1:d5:67:0e"
      cert_thumbprint     = "3A3827F0D9440B87EE0D9921F213FE931C1D1B9D"
      cert_valid_from     = "2025-11-12"
      cert_valid_to       = "2026-11-12"

      country             = "US"
      state               = "Wyoming"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "2025-001805705"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "64:a0:1f:e7:a8:11:9b:43:6b:ae:51:8a:d1:d5:67:0e"
      )
}
