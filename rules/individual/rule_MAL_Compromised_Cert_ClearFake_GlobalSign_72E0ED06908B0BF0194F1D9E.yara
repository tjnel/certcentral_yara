import "pe"

rule MAL_Compromised_Cert_ClearFake_GlobalSign_72E0ED06908B0BF0194F1D9E {
   meta:
      description         = "Detects ClearFake with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-11"
      version             = "1.0"

      hash                = "984c53328f4b199b884d24f41b6b97ee888ec40d16704388fac243dd76e49578"
      malware             = "ClearFake"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CubTiger Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "72:e0:ed:06:90:8b:0b:f0:19:4f:1d:9e"
      cert_thumbprint     = "EDEDF98CBEF23C401CFA4D8B01C4EC3D4C770384"
      cert_valid_from     = "2024-10-11"
      cert_valid_to       = "2025-10-12"

      country             = "CN"
      state               = "Beijing"
      locality            = "Beijing"
      email               = "???"
      rdn_serial_number   = "91110229MA01R14F61"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "72:e0:ed:06:90:8b:0b:f0:19:4f:1d:9e"
      )
}
