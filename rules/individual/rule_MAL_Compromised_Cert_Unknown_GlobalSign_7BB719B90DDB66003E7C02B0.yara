import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_7BB719B90DDB66003E7C02B0 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-31"
      version             = "1.0"

      hash                = "80d66d1e0d1a342c0b3637b09ec83e86a6ce0083788c7cc3c412d5233fa4470c"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "COMPRESSIVE INFRACON LLP"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7b:b7:19:b9:0d:db:66:00:3e:7c:02:b0"
      cert_thumbprint     = "9F41626EDCA4756AA5CA2A3344F52DC021400110"
      cert_valid_from     = "2025-07-31"
      cert_valid_to       = "2026-08-01"

      country             = "IN"
      state               = "Delhi"
      locality            = "Delhi"
      email               = "amit.compressiveinfra@gmail.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7b:b7:19:b9:0d:db:66:00:3e:7c:02:b0"
      )
}
