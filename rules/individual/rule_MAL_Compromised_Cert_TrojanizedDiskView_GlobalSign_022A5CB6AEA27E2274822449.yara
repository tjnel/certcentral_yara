import "pe"

rule MAL_Compromised_Cert_TrojanizedDiskView_GlobalSign_022A5CB6AEA27E2274822449 {
   meta:
      description         = "Detects TrojanizedDiskView with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-02"
      version             = "1.0"

      hash                = "2d9aa7d032f1bce7932c36e2b164c90badc68080e2e917e4cd24266f504cbfa1"
      malware             = "TrojanizedDiskView"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC GlobalGoods Supply"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "02:2a:5c:b6:ae:a2:7e:22:74:82:24:49"
      cert_thumbprint     = "137A346A7DF9273EAE3D1C92AA1CF7925125D79F"
      cert_valid_from     = "2025-04-02"
      cert_valid_to       = "2026-04-03"

      country             = "KG"
      state               = "Bishkek"
      locality            = "Bishkek"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "02:2a:5c:b6:ae:a2:7e:22:74:82:24:49"
      )
}
