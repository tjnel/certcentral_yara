import "pe"

rule MAL_Compromised_Cert_PDF_Spark_GlobalSign_7BF01F1C79B42C10A321CBE6 {
   meta:
      description         = "Detects PDF Spark with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-24"
      version             = "1.0"

      hash                = "cb54030ecafc2af39c03bf0fc80fdc5de11764249bdca85c81457f3fcf9bc201"
      malware             = "PDF Spark"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Eman Group, LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7b:f0:1f:1c:79:b4:2c:10:a3:21:cb:e6"
      cert_thumbprint     = "702813CD746BA6CBA5DDE0F31FDAB1EA735353BD"
      cert_valid_from     = "2025-02-24"
      cert_valid_to       = "2026-02-25"

      country             = "US"
      state               = "New York"
      locality            = "New York"
      email               = "???"
      rdn_serial_number   = "2021-000993778"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7b:f0:1f:1c:79:b4:2c:10:a3:21:cb:e6"
      )
}
