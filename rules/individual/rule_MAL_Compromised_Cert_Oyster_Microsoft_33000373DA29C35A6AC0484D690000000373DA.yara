import "pe"

rule MAL_Compromised_Cert_Oyster_Microsoft_33000373DA29C35A6AC0484D690000000373DA {
   meta:
      description         = "Detects Oyster with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-28"
      version             = "1.0"

      hash                = "0ada29254a6f60816b648c8247d46f1eb122439137f93c91388da2c0d4586550"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "TOLEDO SOFTWARE LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:03:73:da:29:c3:5a:6a:c0:48:4d:69:00:00:00:03:73:da"
      cert_thumbprint     = "EE70CAA544AFDFF40ED83528B637A7651B3EAA3C"
      cert_valid_from     = "2025-06-28"
      cert_valid_to       = "2025-07-01"

      country             = "US"
      state               = "Ohio"
      locality            = "Toledo"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:03:73:da:29:c3:5a:6a:c0:48:4d:69:00:00:00:03:73:da"
      )
}
