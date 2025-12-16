import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330005807C36352DBA0F6900A000000005807C {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-29"
      version             = "1.0"

      hash                = "1dd4039f737b824e838aea6d13126b18377fda239777e5c38c1bc3b409ad07a9"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "JAMES BARRIERE FOUNDATION FOR THE UNDERPRIVILEGED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:05:80:7c:36:35:2d:ba:0f:69:00:a0:00:00:00:05:80:7c"
      cert_thumbprint     = "EA31234FDD415B49086C0CD8BBD3D9950E997AAB"
      cert_valid_from     = "2025-11-29"
      cert_valid_to       = "2025-12-02"

      country             = "CA"
      state               = "Québec"
      locality            = "MONTREAL"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:05:80:7c:36:35:2d:ba:0f:69:00:a0:00:00:00:05:80:7c"
      )
}
