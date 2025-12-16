import "pe"

rule MAL_Compromised_Cert_Oyster_GlobalSign_14DE6008EE49B48E31CDA252 {
   meta:
      description         = "Detects Oyster with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-03"
      version             = "1.0"

      hash                = "3d22a974677164d6bd7166e521e96d07cd00c884b0aeacb5555505c6a62a1c26"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "LLC Infomed22"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "14:de:60:08:ee:49:b4:8e:31:cd:a2:52"
      cert_thumbprint     = "12CFA8824939504311DA5F35A52A16743199FB1E"
      cert_valid_from     = "2025-07-03"
      cert_valid_to       = "2026-07-04"

      country             = "RU"
      state               = "Republic of Bashkortostan"
      locality            = "Ishimbay"
      email               = "???"
      rdn_serial_number   = "1220200021557"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "14:de:60:08:ee:49:b4:8e:31:cd:a2:52"
      )
}
