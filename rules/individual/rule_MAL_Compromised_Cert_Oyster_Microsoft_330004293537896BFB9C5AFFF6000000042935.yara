import "pe"

rule MAL_Compromised_Cert_Oyster_Microsoft_330004293537896BFB9C5AFFF6000000042935 {
   meta:
      description         = "Detects Oyster with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-27"
      version             = "1.0"

      hash                = "51c85e40fb4f5bc3fd872261ffef181485791e2ffbe84ab96227461040a1ca4d"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "TOLEDO SOFTWARE LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:04:29:35:37:89:6b:fb:9c:5a:ff:f6:00:00:00:04:29:35"
      cert_thumbprint     = "AA330263723DDE937F070D2018F29DB7EE05E9B4"
      cert_valid_from     = "2025-06-27"
      cert_valid_to       = "2025-06-30"

      country             = "US"
      state               = "Ohio"
      locality            = "Toledo"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:04:29:35:37:89:6b:fb:9c:5a:ff:f6:00:00:00:04:29:35"
      )
}
