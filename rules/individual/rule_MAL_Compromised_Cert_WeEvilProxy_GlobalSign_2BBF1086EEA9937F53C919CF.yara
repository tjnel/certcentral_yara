import "pe"

rule MAL_Compromised_Cert_WeEvilProxy_GlobalSign_2BBF1086EEA9937F53C919CF {
   meta:
      description         = "Detects WeEvilProxy with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-10"
      version             = "1.0"

      hash                = "5f1e34873b39ae174dda32296ec2fd7347487def3480450f7c327f3fb9587090"
      malware             = "WeEvilProxy"
      malware_type        = "Infostealer"
      malware_notes       = "This malware primarily targets cryptocurrencies. It is distributed through advertisements targing crypto users: https://labs.withsecure.com/publications/weevilproxy"

      signer              = "LLC DITRIX"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "2b:bf:10:86:ee:a9:93:7f:53:c9:19:cf"
      cert_thumbprint     = "D7340B019C3FC16FA659325EB16AC4821FD7D070"
      cert_valid_from     = "2025-04-10"
      cert_valid_to       = "2026-04-11"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1047796821434"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "2b:bf:10:86:ee:a9:93:7f:53:c9:19:cf"
      )
}
