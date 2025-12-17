import "pe"

rule MAL_Compromised_Cert_WeEvilProxy_GlobalSign_72ED6A7A94922577560198BC {
   meta:
      description         = "Detects WeEvilProxy with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-01"
      version             = "1.0"

      hash                = "fb35436322e9429a498f79b9abea24ca419fafab93117582c3e97f9beab3a034"
      malware             = "WeEvilProxy"
      malware_type        = "Infostealer"
      malware_notes       = "This malware primarily targets cryptocurrencies. It is distributed through advertisements targing crypto users: https://labs.withsecure.com/publications/weevilproxy"

      signer              = "LLC Promtrade"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "72:ed:6a:7a:94:92:25:77:56:01:98:bc"
      cert_thumbprint     = "EABE656511CB509B2EF42FC86077010C40F03FF2"
      cert_valid_from     = "2025-05-01"
      cert_valid_to       = "2026-05-02"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "72:ed:6a:7a:94:92:25:77:56:01:98:bc"
      )
}
