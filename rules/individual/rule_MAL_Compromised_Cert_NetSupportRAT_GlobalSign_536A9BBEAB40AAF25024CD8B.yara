import "pe"

rule MAL_Compromised_Cert_NetSupportRAT_GlobalSign_536A9BBEAB40AAF25024CD8B {
   meta:
      description         = "Detects NetSupportRAT with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-03"
      version             = "1.0"

      hash                = "f4615a9c1a9f922536e1ffdd0264ce6c94ef84534ff27b35bd93f1c818eaa743"
      malware             = "NetSupportRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "LLC GrandStroy"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "53:6a:9b:be:ab:40:aa:f2:50:24:cd:8b"
      cert_thumbprint     = "29EB40C0EFE05D01210D6F3197F854E214CB5A3B"
      cert_valid_from     = "2025-06-03"
      cert_valid_to       = "2026-06-04"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1091103000922"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "53:6a:9b:be:ab:40:aa:f2:50:24:cd:8b"
      )
}
