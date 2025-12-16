import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_3C78C533A40E2049443DE9E079C14E1F {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-10"
      version             = "1.0"

      hash                = "fc939537045f4ebddfae0d3588bffdc5727cbf3dd3b1c5a5379796de3f844d98"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ali LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "3c:78:c5:33:a4:0e:20:49:44:3d:e9:e0:79:c1:4e:1f"
      cert_thumbprint     = "D3CD0F6C12CBFE3A00CCAA4D58C26669D57FC671"
      cert_valid_from     = "2025-11-10"
      cert_valid_to       = "2026-07-11"

      country             = "US"
      state               = "Florida"
      locality            = "Palm City"
      email               = "???"
      rdn_serial_number   = "L24000239498"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "3c:78:c5:33:a4:0e:20:49:44:3d:e9:e0:79:c1:4e:1f"
      )
}
