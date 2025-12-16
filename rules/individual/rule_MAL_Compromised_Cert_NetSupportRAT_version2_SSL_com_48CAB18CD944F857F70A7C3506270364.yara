import "pe"

rule MAL_Compromised_Cert_NetSupportRAT_version2_SSL_com_48CAB18CD944F857F70A7C3506270364 {
   meta:
      description         = "Detects NetSupportRAT_version2 with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-07-24"
      version             = "1.0"

      hash                = "6e3084fc8efa08cfa3d95b2c78042092d13a31075714ff1b4af979a01e44dfbc"
      malware             = "NetSupportRAT_version2"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Gesellschaft für Softwareentwicklung und Analytik GmbH"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "48:ca:b1:8c:d9:44:f8:57:f7:0a:7c:35:06:27:03:64"
      cert_thumbprint     = "F19B05B2C406A06B1A801B170955F1693C84C9C6"
      cert_valid_from     = "2020-07-24"
      cert_valid_to       = "2023-07-24"

      country             = "DE"
      state               = "Mecklenburg Vorpommern"
      locality            = "Rostock"
      email               = "???"
      rdn_serial_number   = "HRB 12514"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "48:ca:b1:8c:d9:44:f8:57:f7:0a:7c:35:06:27:03:64"
      )
}
