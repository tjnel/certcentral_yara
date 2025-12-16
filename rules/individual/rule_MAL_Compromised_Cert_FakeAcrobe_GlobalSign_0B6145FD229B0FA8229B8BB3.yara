import "pe"

rule MAL_Compromised_Cert_FakeAcrobe_GlobalSign_0B6145FD229B0FA8229B8BB3 {
   meta:
      description         = "Detects FakeAcrobe with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-10"
      version             = "1.0"

      hash                = "e9f2e382c45d3de8228e87c2ec1254c3d71eeae82d53eec58101e9ce5e8cb088"
      malware             = "FakeAcrobe"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Lotion"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0b:61:45:fd:22:9b:0f:a8:22:9b:8b:b3"
      cert_thumbprint     = "166D6B4CDBFFF2F6F937E3C6939DAFB666AFA0BF"
      cert_valid_from     = "2025-07-10"
      cert_valid_to       = "2026-07-11"

      country             = "RU"
      state               = "Vologda Oblast"
      locality            = "Vologda"
      email               = "oleg-babin@internet.ru"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0b:61:45:fd:22:9b:0f:a8:22:9b:8b:b3"
      )
}
