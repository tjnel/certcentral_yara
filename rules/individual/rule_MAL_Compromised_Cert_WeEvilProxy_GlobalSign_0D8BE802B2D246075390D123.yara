import "pe"

rule MAL_Compromised_Cert_WeEvilProxy_GlobalSign_0D8BE802B2D246075390D123 {
   meta:
      description         = "Detects WeEvilProxy with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-27"
      version             = "1.0"

      hash                = "01c3b49ff55dfbe738b6c9370681b1985abd34641a75803fea1468e102b726c9"
      malware             = "WeEvilProxy"
      malware_type        = "Infostealer"
      malware_notes       = "This malware primarily targets cryptocurrencies. It is distributed through advertisements targing crypto users: https://labs.withsecure.com/publications/weevilproxy"

      signer              = "LLC Gazovaya Kompaniya"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0d:8b:e8:02:b2:d2:46:07:53:90:d1:23"
      cert_thumbprint     = "A301ADB5BC8DB6096B09E729C1E420580652DFB9"
      cert_valid_from     = "2025-05-27"
      cert_valid_to       = "2026-05-28"

      country             = "RU"
      state               = "Chelyabinsk Oblast"
      locality            = "Miass"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0d:8b:e8:02:b2:d2:46:07:53:90:d1:23"
      )
}
