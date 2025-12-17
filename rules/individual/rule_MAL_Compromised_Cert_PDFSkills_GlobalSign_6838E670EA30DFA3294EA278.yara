import "pe"

rule MAL_Compromised_Cert_PDFSkills_GlobalSign_6838E670EA30DFA3294EA278 {
   meta:
      description         = "Detects PDFSkills with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-02-26"
      version             = "1.0"

      hash                = "9c9cdb1a91444dc9c99df071f2dac4791d20112e0df786da40069a1e76594803"
      malware             = "PDFSkills"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "RED ROOT LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "68:38:e6:70:ea:30:df:a3:29:4e:a2:78"
      cert_thumbprint     = "D9AFF96830351EB0B8B219729D110822448FE511"
      cert_valid_from     = "2024-02-26"
      cert_valid_to       = "2025-02-26"

      country             = "IL"
      state               = "Central District"
      locality            = "Ra'anana"
      email               = "info@redrootltd.com"
      rdn_serial_number   = "516201936"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "68:38:e6:70:ea:30:df:a3:29:4e:a2:78"
      )
}
