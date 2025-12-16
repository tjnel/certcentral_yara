import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_GlobalSign_2C2E778927A4B2AB24D0130E {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-25"
      version             = "1.0"

      hash                = "bd403309f8f43fc34d64917720f55c1dbcc50f250f1210bc8dec6c704d4ed461"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "HA NOI TROPICAL ARCHIETECTURE COMPANY LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "2c:2e:77:89:27:a4:b2:ab:24:d0:13:0e"
      cert_thumbprint     = "B5AB41E0B831205309D6E74C1A2109AE20413BCB"
      cert_valid_from     = "2024-07-25"
      cert_valid_to       = "2025-07-23"

      country             = "VN"
      state               = "Ha Noi"
      locality            = "Ha Noi"
      email               = "???"
      rdn_serial_number   = "0104861814"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "2c:2e:77:89:27:a4:b2:ab:24:d0:13:0e"
      )
}
