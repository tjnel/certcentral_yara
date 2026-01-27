import "pe"

rule MAL_Compromised_Cert_Unknown_DigiCert_0D3EEC6D46A8626501C413B6717FBBD7 {
   meta:
      description         = "Detects Unknown with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-04"
      version             = "1.0"

      hash                = "08ac704a57afdbad398ff68afc9bbd55e23d160dc82589fcd35c6eef8968df04"
      malware             = "Unknown"
      malware_type        = "Loader"
      malware_notes       = "Executable was named DocSigning and DocFastSign. This revoked certificate was identified due to the signer being leveraged in a campaign from another certificate issuer."

      signer              = "SOFT CURLS LIMITED"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0d:3e:ec:6d:46:a8:62:65:01:c4:13:b6:71:7f:bb:d7"
      cert_thumbprint     = "E2A565034DFF5EDB2116CDC3EC4C2109FD8D0C8F"
      cert_valid_from     = "2025-02-04"
      cert_valid_to       = "2026-01-14"

      country             = "GB"
      state               = "???"
      locality            = "Tilbury"
      email               = "???"
      rdn_serial_number   = "10918381"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0d:3e:ec:6d:46:a8:62:65:01:c4:13:b6:71:7f:bb:d7"
      )
}
