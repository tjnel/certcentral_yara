import "pe"

rule MAL_Compromised_Cert_WeEvilProxy_GlobalSign_56B3CD7E23410ECB1C9E4394 {
   meta:
      description         = "Detects WeEvilProxy with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-19"
      version             = "1.0"

      hash                = "d781e95428147e6fd463a1de16c740f87415ccf0511f07559c3d79c635c313a5"
      malware             = "WeEvilProxy"
      malware_type        = "Infostealer"
      malware_notes       = "This malware primarily targets cryptocurrencies. It is distributed through advertisements targing crypto users: https://labs.withsecure.com/publications/weevilproxy"

      signer              = "LLC Lusso"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "56:b3:cd:7e:23:41:0e:cb:1c:9e:43:94"
      cert_thumbprint     = "A9BDCEE394EE4963207F4937AA600A5BE9B81F78"
      cert_valid_from     = "2025-06-19"
      cert_valid_to       = "2026-06-20"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "56:b3:cd:7e:23:41:0e:cb:1c:9e:43:94"
      )
}
