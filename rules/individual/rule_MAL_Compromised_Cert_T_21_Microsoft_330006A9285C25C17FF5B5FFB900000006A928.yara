import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_330006A9285C25C17FF5B5FFB900000006A928 {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-24"
      version             = "1.0"

      hash                = "40adf1aaa86dbe99cafa24fcfc7847fac976fc3d01d07cc6a774970028bbffdd"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = "Fake Webex builds delivered from fake meeting websites impersonating companies worldwide"

      signer              = "LAKESIDE TRANSMISSION INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:06:a9:28:5c:25:c1:7f:f5:b5:ff:b9:00:00:00:06:a9:28"
      cert_thumbprint     = "6F078EA198DA76F63B219F65588DD49CD3B5B4B4"
      cert_valid_from     = "2026-01-24"
      cert_valid_to       = "2026-01-27"

      country             = "US"
      state               = "Michigan"
      locality            = "MT CLEMENS"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:06:a9:28:5c:25:c1:7f:f5:b5:ff:b9:00:00:00:06:a9:28"
      )
}
