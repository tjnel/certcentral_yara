import "pe"

rule MAL_Compromised_Cert_Oyster_Microsoft_330004DF75475E1045FF87DE4200000004DF75 {
   meta:
      description         = "Detects Oyster with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-17"
      version             = "1.0"

      hash                = "b52dddf4022ee45243ad01705d5a8d5070cd62aa89174f1ab83f5b58f66d577a"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "Chidiac Entreprises Commerciales Inc."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:04:df:75:47:5e:10:45:ff:87:de:42:00:00:00:04:df:75"
      cert_thumbprint     = "3C8979488316F223F882BCBBA527BB7D9D96A9AF"
      cert_valid_from     = "2025-10-17"
      cert_valid_to       = "2025-10-20"

      country             = "CA"
      state               = "Québec"
      locality            = "MONTREAL"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:04:df:75:47:5e:10:45:ff:87:de:42:00:00:00:04:df:75"
      )
}
