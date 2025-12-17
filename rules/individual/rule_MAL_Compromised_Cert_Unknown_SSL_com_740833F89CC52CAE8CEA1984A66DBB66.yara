import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_740833F89CC52CAE8CEA1984A66DBB66 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-30"
      version             = "1.0"

      hash                = "882759dd0f306ab06f597c2db3011e82eff5bb7515de5d28a20b6913fe7f5626"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ConsolHQ LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "74:08:33:f8:9c:c5:2c:ae:8c:ea:19:84:a6:6d:bb:66"
      cert_thumbprint     = "787863161875446360E7486D3CF5E34E15DC8009"
      cert_valid_from     = "2024-08-30"
      cert_valid_to       = "2025-08-30"

      country             = "GB"
      state               = "???"
      locality            = "Erith"
      email               = "???"
      rdn_serial_number   = "12800651"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "74:08:33:f8:9c:c5:2c:ae:8c:ea:19:84:a6:6d:bb:66"
      )
}
