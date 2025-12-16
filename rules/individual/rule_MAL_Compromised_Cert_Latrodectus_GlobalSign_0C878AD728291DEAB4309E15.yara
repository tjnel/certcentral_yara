import "pe"

rule MAL_Compromised_Cert_Latrodectus_GlobalSign_0C878AD728291DEAB4309E15 {
   meta:
      description         = "Detects Latrodectus with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-03"
      version             = "1.0"

      hash                = "94479572d99e07c50d39c46c8a96843e1c8ae80ce126ae3ba4c4fd223e3d731a"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Tim Instruments Limited Liability Company"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0c:87:8a:d7:28:29:1d:ea:b4:30:9e:15"
      cert_thumbprint     = "039C2AD6862683DEFE39B84D12D9FDC0FBB37EA3"
      cert_valid_from     = "2025-04-03"
      cert_valid_to       = "2026-04-04"

      country             = "KG"
      state               = "Bishkek"
      locality            = "Bishkek"
      email               = "info@techintrum.com"
      rdn_serial_number   = "204348-3300-OOO"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0c:87:8a:d7:28:29:1d:ea:b4:30:9e:15"
      )
}
