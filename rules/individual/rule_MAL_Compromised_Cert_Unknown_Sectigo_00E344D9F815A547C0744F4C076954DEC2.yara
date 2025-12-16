import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_00E344D9F815A547C0744F4C076954DEC2 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-04"
      version             = "1.0"

      hash                = "502f2485bf50fed52326de41cee68d08f4c0cb5fbe2383ae1f03f5bdc87d2e1e"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Infinix Technologies"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:e3:44:d9:f8:15:a5:47:c0:74:4f:4c:07:69:54:de:c2"
      cert_thumbprint     = "E761EB1F9731DBF0E3995982F783F2CC95AA3D1A"
      cert_valid_from     = "2025-02-04"
      cert_valid_to       = "2026-02-04"

      country             = "IN"
      state               = "Karnataka"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "UDYAM-KR-03-0175583"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:e3:44:d9:f8:15:a5:47:c0:74:4f:4c:07:69:54:de:c2"
      )
}
