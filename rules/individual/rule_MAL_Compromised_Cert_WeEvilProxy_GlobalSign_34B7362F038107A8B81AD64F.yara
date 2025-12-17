import "pe"

rule MAL_Compromised_Cert_WeEvilProxy_GlobalSign_34B7362F038107A8B81AD64F {
   meta:
      description         = "Detects WeEvilProxy with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-25"
      version             = "1.0"

      hash                = "5c0c17f5c2f3371e3dcfaeee5c68f54b97a62e1d08dffb48f50513637ae06a86"
      malware             = "WeEvilProxy"
      malware_type        = "Infostealer"
      malware_notes       = "This malware primarily targets cryptocurrencies. It is distributed through advertisements targing crypto users: https://labs.withsecure.com/publications/weevilproxy"

      signer              = "LLC Professional"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "34:b7:36:2f:03:81:07:a8:b8:1a:d6:4f"
      cert_thumbprint     = "9875F3395C8EEB0008D6A92535D769BF38DB9D64"
      cert_valid_from     = "2025-06-25"
      cert_valid_to       = "2026-06-26"

      country             = "RU"
      state               = "Chelyabinsk Oblast"
      locality            = "Magnitogorsk"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "34:b7:36:2f:03:81:07:a8:b8:1a:d6:4f"
      )
}
