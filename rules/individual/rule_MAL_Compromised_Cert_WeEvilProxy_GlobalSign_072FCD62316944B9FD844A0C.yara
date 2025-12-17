import "pe"

rule MAL_Compromised_Cert_WeEvilProxy_GlobalSign_072FCD62316944B9FD844A0C {
   meta:
      description         = "Detects WeEvilProxy with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-19"
      version             = "1.0"

      hash                = "0592b13ded6c3a5ab5ec5aff7ba704ba26f22587027ebd1277797519beb9b164"
      malware             = "WeEvilProxy"
      malware_type        = "Infostealer"
      malware_notes       = "This malware primarily targets cryptocurrencies. It is distributed through advertisements targing crypto users: https://labs.withsecure.com/publications/weevilproxy"

      signer              = "LLC Ecoenergoresurs"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "07:2f:cd:62:31:69:44:b9:fd:84:4a:0c"
      cert_thumbprint     = "BF114710C202BA6436ABF95CFC8B3D2FB39ACEA9"
      cert_valid_from     = "2025-06-19"
      cert_valid_to       = "2026-06-20"

      country             = "RU"
      state               = "Novosibirsk Oblast"
      locality            = "Novosibirsk"
      email               = "???"
      rdn_serial_number   = "1235400034352"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "07:2f:cd:62:31:69:44:b9:fd:84:4a:0c"
      )
}
