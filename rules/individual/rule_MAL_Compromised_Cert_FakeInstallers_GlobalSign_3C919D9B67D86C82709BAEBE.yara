import "pe"

rule MAL_Compromised_Cert_FakeInstallers_GlobalSign_3C919D9B67D86C82709BAEBE {
   meta:
      description         = "Detects FakeInstallers with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-05"
      version             = "1.0"

      hash                = "e4ee1aa6bdaec43ef4cf3b600dacde96af124b999c32d84db6d7241f8bd2ea07"
      malware             = "FakeInstallers"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "THINH HA TRADE & TRANSPORT COMPANY LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3c:91:9d:9b:67:d8:6c:82:70:9b:ae:be"
      cert_thumbprint     = "AB24D90088721235EB94968B7ED7FDCAD118D5AA"
      cert_valid_from     = "2025-05-05"
      cert_valid_to       = "2026-04-02"

      country             = "VN"
      state               = "Ha Nam"
      locality            = "Ha Nam"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3c:91:9d:9b:67:d8:6c:82:70:9b:ae:be"
      )
}
