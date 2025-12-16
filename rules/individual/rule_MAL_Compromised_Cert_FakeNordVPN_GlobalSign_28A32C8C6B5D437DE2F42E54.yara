import "pe"

rule MAL_Compromised_Cert_FakeNordVPN_GlobalSign_28A32C8C6B5D437DE2F42E54 {
   meta:
      description         = "Detects FakeNordVPN with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-19"
      version             = "1.0"

      hash                = "d17a330bb7c929efffb8a42d6ca224f839548560603f88e432043735d392bc85"
      malware             = "FakeNordVPN"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Plan B"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "28:a3:2c:8c:6b:5d:43:7d:e2:f4:2e:54"
      cert_thumbprint     = "5C681ECB281491AC7411949AA1E54E12ED92DF2A"
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
         sig.serial == "28:a3:2c:8c:6b:5d:43:7d:e2:f4:2e:54"
      )
}
