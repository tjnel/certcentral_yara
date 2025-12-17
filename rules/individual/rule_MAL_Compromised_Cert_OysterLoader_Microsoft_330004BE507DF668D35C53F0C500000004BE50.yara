import "pe"

rule MAL_Compromised_Cert_OysterLoader_Microsoft_330004BE507DF668D35C53F0C500000004BE50 {
   meta:
      description         = "Detects OysterLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-10"
      version             = "1.0"

      hash                = "f79ca66eba8c25d4e96b5afafbe1299c0d1e73816c6668df827776ad8362a5de"
      malware             = "OysterLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "ECHO PADDLES INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:04:be:50:7d:f6:68:d3:5c:53:f0:c5:00:00:00:04:be:50"
      cert_thumbprint     = "7DA67F4A21734AFA39F1DE8EA2C21823773530C3"
      cert_valid_from     = "2025-10-10"
      cert_valid_to       = "2025-10-13"

      country             = "CA"
      state               = "Québec"
      locality            = "Wakefield"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:04:be:50:7d:f6:68:d3:5c:53:f0:c5:00:00:00:04:be:50"
      )
}
