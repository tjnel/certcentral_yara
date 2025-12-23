import "pe"

rule MAL_Compromised_Cert_GPUGate_GlobalSign_76DBA39518898AC66E6D1100 {
   meta:
      description         = "Detects GPUGate with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-03"
      version             = "1.0"

      hash                = "933bee136c21e0fbe60bab51dfdffa93562517ff46c03f82ea008c8a21f51d58"
      malware             = "GPUGate"
      malware_type        = "Initial access tool"
      malware_notes       = "Malware was dropped disguised as Docker Desktop. See writeup for more details: https://medium.com/@maurice.fielenbach/malvertising-leads-to-fake-dockerdesktop-exe-gpugate-dropper-a320f8bf7f89"

      signer              = "BARBELL BETTIES LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "76:db:a3:95:18:89:8a:c6:6e:6d:11:00"
      cert_thumbprint     = "E3A575592965242098D03D9B438302D76123DBCC"
      cert_valid_from     = "2025-12-03"
      cert_valid_to       = "2026-12-04"

      country             = "GB"
      state               = "Durham"
      locality            = "Stanley"
      email               = "sewell.c@barbell-betties.uk"
      rdn_serial_number   = "08616935"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "76:db:a3:95:18:89:8a:c6:6e:6d:11:00"
      )
}
