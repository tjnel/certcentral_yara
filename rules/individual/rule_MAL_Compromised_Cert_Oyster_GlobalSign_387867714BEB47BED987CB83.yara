import "pe"

rule MAL_Compromised_Cert_Oyster_GlobalSign_387867714BEB47BED987CB83 {
   meta:
      description         = "Detects Oyster with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-26"
      version             = "1.0"

      hash                = "2e34b7e186e2a40c25177b573981c5c817c104f91a58a93a2e1bd1a0bbfd596a"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "LLC Abris"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "38:78:67:71:4b:eb:47:be:d9:87:cb:83"
      cert_thumbprint     = "3C19819D63233B5D516B6D45F2FA8FC6A6EB7989"
      cert_valid_from     = "2025-06-26"
      cert_valid_to       = "2026-06-27"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "38:78:67:71:4b:eb:47:be:d9:87:cb:83"
      )
}
