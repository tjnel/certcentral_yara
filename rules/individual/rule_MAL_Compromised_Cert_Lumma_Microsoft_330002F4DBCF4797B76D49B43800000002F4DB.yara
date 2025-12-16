import "pe"

rule MAL_Compromised_Cert_Lumma_Microsoft_330002F4DBCF4797B76D49B43800000002F4DB {
   meta:
      description         = "Detects Lumma with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-11"
      version             = "1.0"

      hash                = "708c39e1249e5d40a9a33017d3d3f7cf8f3e6054adb2c2415cd1e4b686e9373e"
      malware             = "Lumma"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "超 王"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:02:f4:db:cf:47:97:b7:6d:49:b4:38:00:00:00:02:f4:db"
      cert_thumbprint     = "4D04E81739EA845B47BAFD05EBB6F1A16A293D6C"
      cert_valid_from     = "2025-03-11"
      cert_valid_to       = "2025-03-14"

      country             = "CN"
      state               = "Shanxi"
      locality            = "万荣"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:02:f4:db:cf:47:97:b7:6d:49:b4:38:00:00:00:02:f4:db"
      )
}
