import "pe"

rule MAL_Compromised_Cert_OysterLoader_Microsoft_3300059D7CA689D296AEAC9E1D000000059D7C {
   meta:
      description         = "Detects OysterLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-26"
      version             = "1.0"

      hash                = "ac5065a351313cc522ab6004b98578a2704d2f636fc2ca78764ab239f4f594a3"
      malware             = "OysterLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "NRM NETWORK RISK MANAGEMENT INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:05:9d:7c:a6:89:d2:96:ae:ac:9e:1d:00:00:00:05:9d:7c"
      cert_thumbprint     = "3842E79F105D3BEBD83FD737FFE9A2F11B920FA4"
      cert_valid_from     = "2025-09-26"
      cert_valid_to       = "2025-09-29"

      country             = "CA"
      state               = "Ontario"
      locality            = "MISSISSAUGA"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:05:9d:7c:a6:89:d2:96:ae:ac:9e:1d:00:00:00:05:9d:7c"
      )
}
