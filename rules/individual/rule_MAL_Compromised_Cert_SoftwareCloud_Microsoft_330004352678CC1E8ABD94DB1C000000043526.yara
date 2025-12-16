import "pe"

rule MAL_Compromised_Cert_SoftwareCloud_Microsoft_330004352678CC1E8ABD94DB1C000000043526 {
   meta:
      description         = "Detects SoftwareCloud with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-24"
      version             = "1.0"

      hash                = "14999e35f0c04d70efcaaa0d898f1869021c71ab6663ddce6a5ed38249d0182f"
      malware             = "SoftwareCloud"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "SOFTWARE DESIGN SERVICES LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:04:35:26:78:cc:1e:8a:bd:94:db:1c:00:00:00:04:35:26"
      cert_thumbprint     = "646A384DBF8099E728C71A98DA4D845679A139F5"
      cert_valid_from     = "2025-06-24"
      cert_valid_to       = "2025-06-27"

      country             = "US"
      state               = "New York"
      locality            = "Wallkill"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:04:35:26:78:cc:1e:8a:bd:94:db:1c:00:00:00:04:35:26"
      )
}
