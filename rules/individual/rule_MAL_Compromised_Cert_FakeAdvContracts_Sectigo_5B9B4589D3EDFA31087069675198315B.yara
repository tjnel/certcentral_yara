import "pe"

rule MAL_Compromised_Cert_FakeAdvContracts_Sectigo_5B9B4589D3EDFA31087069675198315B {
   meta:
      description         = "Detects FakeAdvContracts with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-07"
      version             = "1.0"

      hash                = "1d8e7397fb4b7c0d1dbc075e452a8c70a27df580f53040726c20e5a0bf0ff4b9"
      malware             = "FakeAdvContracts"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CÔNG TY TNHH QISOFT"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "5b:9b:45:89:d3:ed:fa:31:08:70:69:67:51:98:31:5b"
      cert_thumbprint     = "BAE24FCC35D6332FA9E56E20B140081EC7A2F8CB"
      cert_valid_from     = "2025-06-07"
      cert_valid_to       = "2026-06-07"

      country             = "VN"
      state               = "Bắc Giang"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "5b:9b:45:89:d3:ed:fa:31:08:70:69:67:51:98:31:5b"
      )
}
