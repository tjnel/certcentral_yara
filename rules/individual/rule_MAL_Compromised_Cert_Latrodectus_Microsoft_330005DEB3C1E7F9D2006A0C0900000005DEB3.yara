import "pe"

rule MAL_Compromised_Cert_Latrodectus_Microsoft_330005DEB3C1E7F9D2006A0C0900000005DEB3 {
   meta:
      description         = "Detects Latrodectus with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-20"
      version             = "1.0"

      hash                = "8113fc3b4f82fb49f8dd853ca8e1275e0dfb06e48f39830708e4437fe8afbdfb"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Chidiac Entreprises Commerciales Inc."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:05:de:b3:c1:e7:f9:d2:00:6a:0c:09:00:00:00:05:de:b3"
      cert_thumbprint     = "3F8DED465BAE2CA72B177076098DA487E0072523"
      cert_valid_from     = "2025-10-20"
      cert_valid_to       = "2025-10-23"

      country             = "CA"
      state               = "Québec"
      locality            = "MONTREAL"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:05:de:b3:c1:e7:f9:d2:00:6a:0c:09:00:00:00:05:de:b3"
      )
}
