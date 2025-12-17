import "pe"

rule MAL_Compromised_Cert_XRed_DigiCert_0D9D72F1DDA9ED4E39F88FCA66081E67 {
   meta:
      description         = "Detects XRed with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-07-01"
      version             = "1.0"

      hash                = "bed60ace690e1e5b186bed92f8a10542082ef415bdf02967ecf6e48e95a331b5"
      malware             = "XRed"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Wuxi Instant Microelectronics Co., Ltd."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0d:9d:72:f1:dd:a9:ed:4e:39:f8:8f:ca:66:08:1e:67"
      cert_thumbprint     = "D433B32FFBEDE8E547211C73D3615B1F7EE7721B"
      cert_valid_from     = "2022-07-01"
      cert_valid_to       = "2025-07-02"

      country             = "CN"
      state               = "江苏省"
      locality            = "无锡市"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0d:9d:72:f1:dd:a9:ed:4e:39:f8:8f:ca:66:08:1e:67"
      )
}
