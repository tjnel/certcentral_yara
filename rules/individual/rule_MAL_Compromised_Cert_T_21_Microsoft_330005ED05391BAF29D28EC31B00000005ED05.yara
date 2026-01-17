import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_330005ED05391BAF29D28EC31B00000005ED05 {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-03"
      version             = "1.0"

      hash                = "9d385e9d3306b65420172a20b3baf7097b3ca5ee0110c03d1ec8a0014532dd9d"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = "Fake Webex Meeting Launchers spread by a traffer group, involved in a malware campaign around a compromised LinkedIn company account, targeting job-seekers with fake crypto-related job offers"

      signer              = "LAKESIDE TRANSMISSION INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:05:ed:05:39:1b:af:29:d2:8e:c3:1b:00:00:00:05:ed:05"
      cert_thumbprint     = "24EFD9EFFED319CE3FC03FFBF2F89D98BD3E70CE"
      cert_valid_from     = "2025-11-03"
      cert_valid_to       = "2025-11-06"

      country             = "US"
      state               = "Michigan"
      locality            = "MT CLEMENS"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:05:ed:05:39:1b:af:29:d2:8e:c3:1b:00:00:00:05:ed:05"
      )
}
