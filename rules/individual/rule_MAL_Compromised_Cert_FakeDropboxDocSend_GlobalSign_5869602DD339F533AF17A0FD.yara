import "pe"

rule MAL_Compromised_Cert_FakeDropboxDocSend_GlobalSign_5869602DD339F533AF17A0FD {
   meta:
      description         = "Detects FakeDropboxDocSend with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-29"
      version             = "1.0"

      hash                = "9d26e35e6d36a867c6343b4f6d1d8c3c5550ea12eb0fc14427aa8d7ae6ca0a49"
      malware             = "FakeDropboxDocSend"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Richester Business Network Inc."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "58:69:60:2d:d3:39:f5:33:af:17:a0:fd"
      cert_thumbprint     = "22DAF715850473FDC2CAB59A12B8AEACDA66CA83"
      cert_valid_from     = "2025-08-29"
      cert_valid_to       = "2026-08-30"

      country             = "CA"
      state               = "Alberta"
      locality            = "Calgary"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "58:69:60:2d:d3:39:f5:33:af:17:a0:fd"
      )
}
