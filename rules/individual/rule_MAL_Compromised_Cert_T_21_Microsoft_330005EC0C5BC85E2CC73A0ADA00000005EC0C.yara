import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_330005EC0C5BC85E2CC73A0ADA00000005EC0C {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-22"
      version             = "1.0"

      hash                = "fa149dee38b5002946cafb025873fdf5a377b52d0a9e971222d4044a36f02232"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = "Fake Webex Meeting Launchers spread by a traffer group, involved in a malware campaign around a compromised LinkedIn company account, targeting job-seekers with fake crypto-related job offers"

      signer              = "LAKESIDE TRANSMISSION INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:05:ec:0c:5b:c8:5e:2c:c7:3a:0a:da:00:00:00:05:ec:0c"
      cert_thumbprint     = "01DB880607C28EFAD003AC732ABF6942B481B416"
      cert_valid_from     = "2025-12-22"
      cert_valid_to       = "2025-12-25"

      country             = "US"
      state               = "Michigan"
      locality            = "MT CLEMENS"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:05:ec:0c:5b:c8:5e:2c:c7:3a:0a:da:00:00:00:05:ec:0c"
      )
}
