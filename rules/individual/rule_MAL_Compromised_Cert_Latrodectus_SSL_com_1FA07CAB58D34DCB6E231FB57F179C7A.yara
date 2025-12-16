import "pe"

rule MAL_Compromised_Cert_Latrodectus_SSL_com_1FA07CAB58D34DCB6E231FB57F179C7A {
   meta:
      description         = "Detects Latrodectus with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-15"
      version             = "1.0"

      hash                = "f1b27d88bdb6b4d2019191b539f130edceb6b7ec16bd4131159256b4c872a8fd"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TEAM PLAYER SOLUTION LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "1f:a0:7c:ab:58:d3:4d:cb:6e:23:1f:b5:7f:17:9c:7a"
      cert_thumbprint     = "1DD29CCAD6E21A5E15BE6DD722D5D2805B28BA83"
      cert_valid_from     = "2025-08-15"
      cert_valid_to       = "2026-08-15"

      country             = "GB"
      state               = "England"
      locality            = "Huntingdon"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "1f:a0:7c:ab:58:d3:4d:cb:6e:23:1f:b5:7f:17:9c:7a"
      )
}
