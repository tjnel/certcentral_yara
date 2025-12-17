import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_1D9ABA861B4A70AE4E3B400D {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-13"
      version             = "1.0"

      hash                = "2ef2d5e126c0508e5a8d9d4d9fa08d60d4987b4ca401a8d2d62c89a8ef4bcc0f"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ALLstore Software-Entwicklungs GmbH"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "1d:9a:ba:86:1b:4a:70:ae:4e:3b:40:0d"
      cert_thumbprint     = "77443D5DB8718CBEBC953CEFF4A8795EDBFB6ABC"
      cert_valid_from     = "2024-12-13"
      cert_valid_to       = "2025-12-14"

      country             = "AT"
      state               = "Vienna"
      locality            = "Vienna"
      email               = "???"
      rdn_serial_number   = "517249k"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "1d:9a:ba:86:1b:4a:70:ae:4e:3b:40:0d"
      )
}
