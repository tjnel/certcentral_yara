import "pe"

rule MAL_Compromised_Cert_Oyster_Latrodectus_Stage2_GlobalSign_104D1BFA90D93794EA361457 {
   meta:
      description         = "Detects Oyster_Latrodectus_Stage2 with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-06"
      version             = "1.0"

      hash                = "13b1d27bb1fa279da12934f1c219baf993b1170c57207d95c4a5aa258c402b6c"
      malware             = "Oyster_Latrodectus_Stage2"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "LLC Nasta"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "10:4d:1b:fa:90:d9:37:94:ea:36:14:57"
      cert_thumbprint     = "610A4DAD49F7B559EC0C81A5610FA7E8D06F99BA"
      cert_valid_from     = "2025-10-06"
      cert_valid_to       = "2026-07-01"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "10:4d:1b:fa:90:d9:37:94:ea:36:14:57"
      )
}
