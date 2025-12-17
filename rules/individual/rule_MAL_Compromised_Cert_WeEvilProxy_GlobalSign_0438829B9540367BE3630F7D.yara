import "pe"

rule MAL_Compromised_Cert_WeEvilProxy_GlobalSign_0438829B9540367BE3630F7D {
   meta:
      description         = "Detects WeEvilProxy with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-29"
      version             = "1.0"

      hash                = "a34bfc8c1c24202c196092d56ed01b498c9f75e10ea7ccd1f923138ca4919be3"
      malware             = "WeEvilProxy"
      malware_type        = "Infostealer"
      malware_notes       = "This malware primarily targets cryptocurrencies. It is distributed through advertisements targing crypto users: https://labs.withsecure.com/publications/weevilproxy"

      signer              = "Lina LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "04:38:82:9b:95:40:36:7b:e3:63:0f:7d"
      cert_thumbprint     = "724D9BCB326E10BE87C318E5339891F6ACD86F74"
      cert_valid_from     = "2025-04-29"
      cert_valid_to       = "2026-04-30"

      country             = "RU"
      state               = "Leningrad Oblast"
      locality            = "Kirovsk"
      email               = "???"
      rdn_serial_number   = "1174704011162"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "04:38:82:9b:95:40:36:7b:e3:63:0f:7d"
      )
}
