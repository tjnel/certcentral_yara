import "pe"

rule MAL_Compromised_Cert_WeEvilProxy_GlobalSign_222199BBBF3A5275FAAF58D5 {
   meta:
      description         = "Detects WeEvilProxy with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-15"
      version             = "1.0"

      hash                = "4297fccd1a4d3508ba166c3d32eaf6ac47a6267d2743eed2793de66d9c16a154"
      malware             = "WeEvilProxy"
      malware_type        = "Infostealer"
      malware_notes       = "This malware primarily targets cryptocurrencies. It is distributed through advertisements targing crypto users: https://labs.withsecure.com/publications/weevilproxy"

      signer              = "LLC Kraft Market"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "22:21:99:bb:bf:3a:52:75:fa:af:58:d5"
      cert_thumbprint     = "A8F4F99311A9B3B59E85A4C2387554638476326D"
      cert_valid_from     = "2025-04-15"
      cert_valid_to       = "2026-04-16"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "22:21:99:bb:bf:3a:52:75:fa:af:58:d5"
      )
}
