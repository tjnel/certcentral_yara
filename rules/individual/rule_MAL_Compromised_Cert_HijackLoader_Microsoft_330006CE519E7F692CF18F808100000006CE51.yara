import "pe"

rule MAL_Compromised_Cert_HijackLoader_Microsoft_330006CE519E7F692CF18F808100000006CE51 {
   meta:
      description         = "Detects HijackLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-06"
      version             = "1.0"

      hash                = "94307191dba3962e5dc121fa2a984a784a951af0c0fc9229571898667e320578"
      malware             = "HijackLoader"
      malware_type        = "Loader"
      malware_notes       = "The malware was distributed as a keypass installer: https://jeromesegura.com/malvertising/2026/01/01-11-2026_KeePass"

      signer              = "FOCUS DIGITAL AGENCY SP Z O O"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:06:ce:51:9e:7f:69:2c:f1:8f:80:81:00:00:00:06:ce:51"
      cert_thumbprint     = "2276CF17FC2E11B61EA9DE89F757DA0ADA0CB35C"
      cert_valid_from     = "2026-01-06"
      cert_valid_to       = "2026-01-09"

      country             = "PL"
      state               = "Mazowieckie"
      locality            = "Warszawa"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:06:ce:51:9e:7f:69:2c:f1:8f:80:81:00:00:00:06:ce:51"
      )
}
