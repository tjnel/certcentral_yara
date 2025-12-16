import "pe"

rule MAL_Compromised_Cert_Latrodectus_Microsoft_330004D9923711B01863EF675A00000004D992 {
   meta:
      description         = "Detects Latrodectus with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-16"
      version             = "1.0"

      hash                = "60e0a433c0114a628856f671e42d21f2e573b1b9b06ba545d77b8e2e12685a2f"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Chidiac Entreprises Commerciales Inc."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:04:d9:92:37:11:b0:18:63:ef:67:5a:00:00:00:04:d9:92"
      cert_thumbprint     = "55CD33E0B48D8D16B1635DA4E02F9501133A2B40"
      cert_valid_from     = "2025-10-16"
      cert_valid_to       = "2025-10-19"

      country             = "CA"
      state               = "Québec"
      locality            = "MONTREAL"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:04:d9:92:37:11:b0:18:63:ef:67:5a:00:00:00:04:d9:92"
      )
}
