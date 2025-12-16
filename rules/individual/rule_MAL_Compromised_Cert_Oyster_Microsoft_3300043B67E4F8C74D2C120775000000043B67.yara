import "pe"

rule MAL_Compromised_Cert_Oyster_Microsoft_3300043B67E4F8C74D2C120775000000043B67 {
   meta:
      description         = "Detects Oyster with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-25"
      version             = "1.0"

      hash                = "dd995934bdab89ca6941633dea1ef6e6d9c3982af5b454ecb0a6c440032b30fb"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "NEW VISION MARKETING LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:04:3b:67:e4:f8:c7:4d:2c:12:07:75:00:00:00:04:3b:67"
      cert_thumbprint     = "51BB5BAEB3D293332FAB7E9A4CC23F406AFB0D94"
      cert_valid_from     = "2025-06-25"
      cert_valid_to       = "2025-06-28"

      country             = "US"
      state               = "Arizona"
      locality            = "Mesa"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:04:3b:67:e4:f8:c7:4d:2c:12:07:75:00:00:00:04:3b:67"
      )
}
