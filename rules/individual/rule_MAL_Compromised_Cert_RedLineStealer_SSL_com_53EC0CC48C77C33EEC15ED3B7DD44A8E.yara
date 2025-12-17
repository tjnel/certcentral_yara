import "pe"

rule MAL_Compromised_Cert_RedLineStealer_SSL_com_53EC0CC48C77C33EEC15ED3B7DD44A8E {
   meta:
      description         = "Detects RedLineStealer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-19"
      version             = "1.0"

      hash                = "73fd02a8b1bdc0b24969a8fbc40471e3cc531d77711cd74ec4358f86b1285c4a"
      malware             = "RedLineStealer"
      malware_type        = "Infostealer"
      malware_notes       = "A malware as a service infostealer: https://www.proofpoint.com/us/blog/threat-insight/new-redline-stealer-distributed-using-coronavirus-themed-email-campaign"

      signer              = "TIMBER DIGITAL LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "53:ec:0c:c4:8c:77:c3:3e:ec:15:ed:3b:7d:d4:4a:8e"
      cert_thumbprint     = "3D470D3F32806CCAD515A88768E8EA0A56CAC919"
      cert_valid_from     = "2024-07-19"
      cert_valid_to       = "2025-07-19"

      country             = "GB"
      state               = "???"
      locality            = "Leamington Spa"
      email               = "???"
      rdn_serial_number   = "12933141"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "53:ec:0c:c4:8c:77:c3:3e:ec:15:ed:3b:7d:d4:4a:8e"
      )
}
