import "pe"

rule MAL_Compromised_Cert_Unknown_Fakebat_Cert_SSL_com_43BD8D6AA3FECB65766396C09E9EEDEA {
   meta:
      description         = "Detects Unknown_Fakebat_Cert with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-01"
      version             = "1.0"

      hash                = "511e21b8c183fee710862aa39fe11cd87d632377b123b0ecba4e979100237f42"
      malware             = "Unknown_Fakebat_Cert"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Tulip Soft Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "43:bd:8d:6a:a3:fe:cb:65:76:63:96:c0:9e:9e:ed:ea"
      cert_thumbprint     = "ED892EDC5950D96116F97900995B1CEE43A12598"
      cert_valid_from     = "2024-06-01"
      cert_valid_to       = "2025-06-01"

      country             = "GB"
      state               = "London Borough of Barking and Dagenham"
      locality            = "Dagenham"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "43:bd:8d:6a:a3:fe:cb:65:76:63:96:c0:9e:9e:ed:ea"
      )
}
