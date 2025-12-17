import "pe"

rule MAL_Compromised_Cert_MeshAgent_GlobalSign_5D35276009EC70A2818D3B24 {
   meta:
      description         = "Detects MeshAgent with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-28"
      version             = "1.0"

      hash                = "bac580330533d88615cff21f12aed1b8e045034f5f7f98875f2edf4b063fe554"
      malware             = "MeshAgent"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC MISTAKE"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5d:35:27:60:09:ec:70:a2:81:8d:3b:24"
      cert_thumbprint     = "104C5A5155DE9062F51F40EE1ABCABC6E369C20B"
      cert_valid_from     = "2025-03-28"
      cert_valid_to       = "2026-03-29"

      country             = "RU"
      state               = "Republic of Kalmykia"
      locality            = "Elista"
      email               = "???"
      rdn_serial_number   = "1220800003160"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5d:35:27:60:09:ec:70:a2:81:8d:3b:24"
      )
}
