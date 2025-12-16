import "pe"

rule MAL_Compromised_Cert_FakeDocument_GlobalSign_2EE2D41E4BD4CD3C3A3CC9B8 {
   meta:
      description         = "Detects FakeDocument with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-17"
      version             = "1.0"

      hash                = "4442e1b545f0a571af113b0cc7455ecba1a603c81bbf84a52b9e61d332f97233"
      malware             = "FakeDocument"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ALVES JUNIOR MAQUINAS E EQUIPAMENTOS LTDA"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "2e:e2:d4:1e:4b:d4:cd:3c:3a:3c:c9:b8"
      cert_thumbprint     = "DC9E774181A736B0437483521835009CAB4E4198"
      cert_valid_from     = "2025-10-17"
      cert_valid_to       = "2026-10-18"

      country             = "BR"
      state               = "GOIAS"
      locality            = "GOIANIA"
      email               = "alvesconstrutorajuridico@gmail.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "2e:e2:d4:1e:4b:d4:cd:3c:3a:3c:c9:b8"
      )
}
