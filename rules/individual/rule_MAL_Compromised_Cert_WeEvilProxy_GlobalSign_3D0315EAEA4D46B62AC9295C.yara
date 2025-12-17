import "pe"

rule MAL_Compromised_Cert_WeEvilProxy_GlobalSign_3D0315EAEA4D46B62AC9295C {
   meta:
      description         = "Detects WeEvilProxy with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-19"
      version             = "1.0"

      hash                = "e48eba9d41a2d46d963c1117604005f53afce3e7e1ac5e0a7cca3b642720e7c2"
      malware             = "WeEvilProxy"
      malware_type        = "Infostealer"
      malware_notes       = "This malware primarily targets cryptocurrencies. It is distributed through advertisements targing crypto users: https://labs.withsecure.com/publications/weevilproxy"

      signer              = "LLC Fashion One"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3d:03:15:ea:ea:4d:46:b6:2a:c9:29:5c"
      cert_thumbprint     = "D84CC8EBF3AB53A22F4824354AEEEC0B59F958CA"
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
         sig.serial == "3d:03:15:ea:ea:4d:46:b6:2a:c9:29:5c"
      )
}
