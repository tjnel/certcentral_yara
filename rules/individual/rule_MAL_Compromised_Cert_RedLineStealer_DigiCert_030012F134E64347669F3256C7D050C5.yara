import "pe"

rule MAL_Compromised_Cert_RedLineStealer_DigiCert_030012F134E64347669F3256C7D050C5 {
   meta:
      description         = "Detects RedLineStealer with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-07-21"
      version             = "1.0"

      hash                = "446edc0d1f7fff55b43dc47d935ac4c8b4ec345a5edaf90f5ea2122d3137f19b"
      malware             = "RedLineStealer"
      malware_type        = "Infostealer"
      malware_notes       = "A malware as a service infostealer: https://www.proofpoint.com/us/blog/threat-insight/new-redline-stealer-distributed-using-coronavirus-themed-email-campaign"

      signer              = "Futumarket LLC"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert EV Code Signing CA (SHA2)"
      cert_serial         = "03:00:12:f1:34:e6:43:47:66:9f:32:56:c7:d0:50:c5"
      cert_thumbprint     = "959CAA354B28892608AB1BB9519424C30BEBC155"
      cert_valid_from     = "2020-07-21"
      cert_valid_to       = "2021-07-26"

      country             = "RU"
      state               = "???"
      locality            = "Saint-Petersburg"
      email               = "???"
      rdn_serial_number   = "1167847450407"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert EV Code Signing CA (SHA2)" and
         sig.serial == "03:00:12:f1:34:e6:43:47:66:9f:32:56:c7:d0:50:c5"
      )
}
