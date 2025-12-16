import "pe"

rule MAL_Compromised_Cert_OysterLoader_Microsoft_3300066515AC0ED03F9FD3F2E2000000066515 {
   meta:
      description         = "Detects OysterLoader with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-23"
      version             = "1.0"

      hash                = "d869ef7d429c6c79bed369217e1b87b05236e35469b3d8264c775dd2dce5757b"
      malware             = "OysterLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "Reach First Inc."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:06:65:15:ac:0e:d0:3f:9f:d3:f2:e2:00:00:00:06:65:15"
      cert_thumbprint     = "EDE64C2A0AA33D0B0043D6B443113611296F4806"
      cert_valid_from     = "2025-11-23"
      cert_valid_to       = "2025-11-26"

      country             = "CA"
      state               = "Alberta"
      locality            = "Edmonton"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:06:65:15:ac:0e:d0:3f:9f:d3:f2:e2:00:00:00:06:65:15"
      )
}
