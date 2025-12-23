import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_124DBD1A2E51CA91DFA90016 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-24"
      version             = "1.0"

      hash                = "58bff33e99a349f6336b4aa1651fb914a4f8580beac135a2edb3bbdc012f4f18"
      malware             = "Unknown"
      malware_type        = "Initial access tool"
      malware_notes       = "The malware was distributed from malicious advertising as documented here: https://jeromesegura.com/malvertising/2025/12/12-21-2025_RVTools. The MSI uses python to execute a compiled python script disguised as LICENSE.txt"

      signer              = "T.R. LAK HOLDING ApS"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "12:4d:bd:1a:2e:51:ca:91:df:a9:00:16"
      cert_thumbprint     = "9BB2144E2CC194F9C2F66135EE5ABF82F16CC608"
      cert_valid_from     = "2025-09-24"
      cert_valid_to       = "2026-09-25"

      country             = "DK"
      state               = "Hovedstaden"
      locality            = "Hedehusene"
      email               = "???"
      rdn_serial_number   = "25628667"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "12:4d:bd:1a:2e:51:ca:91:df:a9:00:16"
      )
}
