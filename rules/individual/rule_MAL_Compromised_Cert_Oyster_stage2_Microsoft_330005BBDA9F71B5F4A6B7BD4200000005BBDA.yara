import "pe"

rule MAL_Compromised_Cert_Oyster_stage2_Microsoft_330005BBDA9F71B5F4A6B7BD4200000005BBDA {
   meta:
      description         = "Detects Oyster_stage2 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-20"
      version             = "1.0"

      hash                = "db16458f707d77cecc73c0f52db943bfd40970d9074f2d405e1fe1fd84fa5b32"
      malware             = "Oyster_stage2"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "Mobiquity Technologies, Inc."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:05:bb:da:9f:71:b5:f4:a6:b7:bd:42:00:00:00:05:bb:da"
      cert_thumbprint     = "1F6461C8CF231A1F1B9B9F2FA899E974B04ED48E"
      cert_valid_from     = "2025-10-20"
      cert_valid_to       = "2025-10-23"

      country             = "US"
      state               = "New York"
      locality            = "Shoreham"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:05:bb:da:9f:71:b5:f4:a6:b7:bd:42:00:00:00:05:bb:da"
      )
}
