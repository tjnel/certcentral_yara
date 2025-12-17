import "pe"

rule MAL_Compromised_Cert_OysterLoader_GlobalSign_569587BA554EAD2539616B50 {
   meta:
      description         = "Detects OysterLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-03"
      version             = "1.0"

      hash                = "455979f3887f9ce119d56291df97dd71a3760676b498689e68495f329489e886"
      malware             = "OysterLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "LLC Aktivstroy"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "56:95:87:ba:55:4e:ad:25:39:61:6b:50"
      cert_thumbprint     = "49137F18750BF8CE41A7F0C95982048AA693406F"
      cert_valid_from     = "2025-07-03"
      cert_valid_to       = "2026-07-04"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1157746898902"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "56:95:87:ba:55:4e:ad:25:39:61:6b:50"
      )
}
