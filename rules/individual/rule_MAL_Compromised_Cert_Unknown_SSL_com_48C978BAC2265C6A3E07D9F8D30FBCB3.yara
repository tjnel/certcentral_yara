import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_48C978BAC2265C6A3E07D9F8D30FBCB3 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-22"
      version             = "1.0"

      hash                = "fbec0950cdb1fcd3193cfac31d48308fd91fb9d155ff628c2e589304df8b3222"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shiyu Bio-Tech Shijiazhuang Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "48:c9:78:ba:c2:26:5c:6a:3e:07:d9:f8:d3:0f:bc:b3"
      cert_thumbprint     = "EA84EE72931C3A07FD35B79F15407380F4241062"
      cert_valid_from     = "2024-08-22"
      cert_valid_to       = "2025-08-22"

      country             = "CN"
      state               = "Hebei"
      locality            = "Shijiazhuang"
      email               = "???"
      rdn_serial_number   = "91130182715863555Y"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "48:c9:78:ba:c2:26:5c:6a:3e:07:d9:f8:d3:0f:bc:b3"
      )
}
