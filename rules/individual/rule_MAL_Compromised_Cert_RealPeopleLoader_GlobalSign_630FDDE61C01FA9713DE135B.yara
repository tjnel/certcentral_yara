import "pe"

rule MAL_Compromised_Cert_RealPeopleLoader_GlobalSign_630FDDE61C01FA9713DE135B {
   meta:
      description         = "Detects RealPeopleLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-28"
      version             = "1.0"

      hash                = "a90dc68f5c888a8e7f922c215ccd2bc7400da17616bcb37aa91a234a6df809ad"
      malware             = "RealPeopleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ezhou Taihaocheng Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "63:0f:dd:e6:1c:01:fa:97:13:de:13:5b"
      cert_thumbprint     = "8E68FA147901336EC6B35728E39151FA543B1EA4"
      cert_valid_from     = "2025-05-28"
      cert_valid_to       = "2026-05-29"

      country             = "CN"
      state               = "Hubei"
      locality            = "Ezhou"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "63:0f:dd:e6:1c:01:fa:97:13:de:13:5b"
      )
}
