import "pe"

rule MAL_Compromised_Cert_StealC_GlobalSign_2A0B54F354DA2C94ABA626C1 {
   meta:
      description         = "Detects StealC with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-20"
      version             = "1.0"

      hash                = "a72304a18fa28a8b75bdc89d1704a9d833fc5146a441ae4fe425741ce137e427"
      malware             = "StealC"
      malware_type        = "Infostealer"
      malware_notes       = "Malware was disguised as a VPN."

      signer              = "OOO Upravlyayushchaya Kompaniya Boksit"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "2a:0b:54:f3:54:da:2c:94:ab:a6:26:c1"
      cert_thumbprint     = "AC0B800F87A27DF2368362857D15FA31D0D91AB3"
      cert_valid_from     = "2025-02-20"
      cert_valid_to       = "2026-02-21"

      country             = "RU"
      state               = "Sankt-Peterburg"
      locality            = "Sankt-Peterburg"
      email               = "dev@safeconvpn.com"
      rdn_serial_number   = "1197847084687"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "2a:0b:54:f3:54:da:2c:94:ab:a6:26:c1"
      )
}
